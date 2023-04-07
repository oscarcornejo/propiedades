import * as config from "../config.js";
import { emailTemplate } from "../helpers/email.js";
import jwt from "jsonwebtoken";
import { hashPassword, comparePassword } from "../helpers/auth.js";
import User from "../models/user.js";
import { nanoid } from "nanoid";
import validator from "email-validator";

const tokenAndUserResponse = (req, res, user) => {
  // create token
  const jwtToken = jwt.sign({ _id: user._id }, config.JWT_SECRET, {
    expiresIn: "1h",
  });

  // create refresh token
  const refreshToken = jwt.sign({ _id: user._id }, config.JWT_SECRET, {
    expiresIn: "7d",
  });

  // hide fields
  user.password = undefined;
  user.resetCode = undefined;

  // send response
  return res.json({
    user,
    token: jwtToken,
    refreshToken,
  });
};

export const welcome = (req, res) => {
  res.json({ data: "hello world from nodejs api" });
};

export const preRegister = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!validator.validate(email)) {
      return res.json({ error: "A valid email is required" });
    }

    if (!password) {
      return res.json({ error: "Password is required" });
    }

    if (password && password.length < 6) {
      return res.json({ error: "Password should be at least 6 characters" });
    }

    const user = await User.findOne({ email });

    if (user) {
      return res.json({ error: "Email is taken" });
    }

    // generate jwt using email and password
    const token = jwt.sign({ email, password }, config.JWT_SECRET, {
      expiresIn: "1h",
    });

    // send test email
    config.AWSSES.sendEmail(
      emailTemplate(
        email,
        `
        <p>Please click the link below to activate your account.</p>
        <a href="${config.CLIENT_URL}/auth/account-activate/${token}">Activate my account</a>
        `,
        config.REPLY_TO,
        "Welcome to Realist app"
      ),
      (err, data) => {
        if (err) {
          console.log("Provide a valid email address", err);
          return res.json({ ok: false });
        } else {
          console.log("Check email to complete registration", data);
          return res.json({ ok: true });
        }
      }
    );
  } catch (err) {
    console.log(err);
  }
};

export const register = async (req, res) => {
  try {
    // decode email, password from token
    const { email, password } = jwt.verify(req.body.token, config.JWT_SECRET);

    const userExist = await User.findOne({ email });

    if (userExist) {
      return res.json({ error: "Email is taken" });
    }

    // hash password
    const hashedPassword = await hashPassword(password);

    // create user and save
    const user = await new User({
      username: nanoid(6),
      email,
      password: hashedPassword,
    }).save();

    tokenAndUserResponse(req, res, user);
  } catch (err) {
    console.log(err);
    res.json({ error: "Invalid or expired token. Try again." });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ error: "Please register first" });
    }

    // 2. compare password
    const match = await comparePassword(password, user.password);
    if (!match) return res.json({ error: "Wrong password" });

    tokenAndUserResponse(req, res, user);
  } catch (err) {
    console.log(err);
    res.json({ error: "Something went wrong. Try again." });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.json({ error: "Could not find user with that email" });
    } else {
      // save to user db
      const resetCode = nanoid();
      user.resetCode = resetCode;
      user.save();

      const token = jwt.sign({ resetCode }, config.JWT_SECRET, {
        expiresIn: "60m",
      });

      // send email
      config.AWSSES.sendEmail(
        emailTemplate(
          email,
          `
        <p>Please click the link below to access your account.</p>
        <a href="${config.CLIENT_URL}/auth/access-password/${token}">Access my account</a>
        `,
          config.REPLY_TO,
          "Access your account"
        ),
        (err, data) => {
          if (err) {
            return res.json({
              ok: false,
              message: "Provide a valid email address",
            });
          } else {
            return res.json({
              ok: true,
              message: "Check email to access your account",
            });
          }
        }
      );
    }
  } catch (err) {
    console.log(err);
    res.json({ error: "Something went wrong. Try again." });
  }
};

export const accessAccount = async (req, res) => {
  console.log(req.body);
  try {
    // verify token and check expiry
    const { resetCode } = jwt.verify(req.body.resetCode, config.JWT_SECRET);
    const user = await User.findOneAndUpdate({ resetCode }, { resetCode: "" });

    tokenAndUserResponse(req, res, user);
  } catch (err) {
    console.log(err);
    res.json({ error: "Expired or invalid token. Try again." });
  }
};

export const refreshToken = async (req, res) => {
  try {
    // console.log("you hit refresh token endpoint => ", req.headers);
    const { _id } = jwt.verify(req.headers.refresh_token, config.JWT_SECRET);
    const user = await User.findById(_id);

    tokenAndUserResponse(req, res, user);
  } catch (err) {
    console.log("===> ", err.name);
    return res.status(403).json({ error: "Refresh token failed" }); // 403 is important
  }
};

export const currentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.password = undefined;
    user.resetCode = undefined;
    res.json(user);
  } catch (err) {
    console.log(err);
    return res.status(403).json({ error: "Unauthorized" });
  }
};

export const publicProfile = async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.userId });
    user.password = undefined;
    user.resetCode = undefined;
    res.json(user);
  } catch (err) {
    console.log(err);
    return res.status(403).json({ error: "User not found" });
  }
};

export const updatePassword = async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.json({ error: "Password is required" });

    // check if password meets the requirement
    if (password && password?.length < 6) {
      return res.json({ error: "Password should be min 6 charactersd" });
    }

    // const user = await User.findById(req.user._id);
    // const hashedPassword = await hashPassword(password);
    // await User.findByIdAndUpdate(user._id, { password: hashedPassword });

    const user = await User.findByIdAndUpdate(req.user._id, {
      password: await hashPassword(password),
    });

    res.json({ ok: true });
  } catch (err) {
    console.log(err);
    return res.status(403).json({ error: "Unauthorized" });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { ...req.body }, //req.body
      { new: true }
    );

    user.password = undefined;
    user.resetCode = undefined;
    res.json(user);
  } catch (err) {
    console.log(err);
    if (err.codeName === "DuplicateKey") {
      return res
        .status(403)
        .json({ error: "Username or Email is already taken" });
    } else {
      return res.status(403).json({ error: "Unauhorized" });
    }
  }
};
