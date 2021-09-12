const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const User = require("../models/user");
const { authenticateJWT } = require("../middleware/auth");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    // authenticate user
    const user = User.authenticate(username, password);
    // if user is authenticated, create token and return
    if (user) {
      const token = jwt.sign({ username }, SECRET_KEY);
      User.updateLoginTimestamp(username);
      return res.json({ token });
    } else {
      throw new ExpressError("Invalid username or password", 400);
    }
  } catch (error) {
    return next(error);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async (req, res, next) => {
  try {
    const { username, password, first_name, last_name, phone } = req.body;
    // register user in DB
    const registeredUser = await User.register(
      username,
      password,
      first_name,
      last_name,
      phone
    );
    if (registeredUser) {
      const token = jwt.sign({ username }, token);
      User.updateLoginTimestamp(username);
      return res.json({ token });
    } else {
      throw new ExpressError("Something went wrong", 400);
    }
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
