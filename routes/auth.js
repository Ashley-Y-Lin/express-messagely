"use strict";

const User = require("../models/user");

const Router = require("express").Router;
const router = new Router();
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const {UnauthorizedError} = require("../expressError")


/** POST /login: {username, password} => {token} */
router.post("/login", async function (req, res, next) {
  if (req.body === undefined) throw new BadRequestError();

  const { username, password } = req.body;

  const isAuthenticated = await User.authenticate(username, password)

  if (isAuthenticated) {
    const token = jwt.sign({ username }, SECRET_KEY);
    console.log(token)
    return res.json({ token });
  } else {
    throw new UnauthorizedError("Invalid user/password");
  }
});

/** POST /register: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 */

router.post("/register", async function (req, res, next) {
  if (req.body === undefined) throw new BadRequestError();
  const { username, password, first_name, last_name, phone } = req.body;

  const newUser = User.register({username, password, first_name, last_name, phone});

  if (newUser) {
    const token = jwt.sign({ username }, SECRET_KEY);
    return res.json({ token });
  } else {
    throw new UnauthorizedError("Invalid user/password");
  }
});


module.exports = router;