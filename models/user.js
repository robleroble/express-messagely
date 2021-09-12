/** User class for message.ly */

const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR } = require("../config");

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register(username, password, first_name, last_name, phone) {
    let hashed_password = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
        RETURNING username, password, first_name, last_name, phone, join_at`,
      [username, hashed_password, first_name, last_name, phone]
    );
    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    // find user
    const userResult = await db.query(
      `SELECT username, password
        FROM users
        WHERE username=$1`,
      [username]
    );
    let hashedPW = userResult.rows[0].password;
    // hash PW and compare with stored DB pw
    if (await bcrypt.compare(password, hashedPW)) {
      return true;
    } else {
      return false;
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
        SET last_login_at = current_timestamp
        WHERE username=$1`,
      [username]
    );
    return result.rows[0];
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(
      `SELECT * 
        FROM users`
    );
    const users = result.rows.map((user) => ({
      first_name: user.first_name,
      last_name: user.last_name,
      phone: user.phone,
      username: user.username,
    }));
    return users;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `SELECT *
        FROM users
        WHERE username=$1`,
      [username]
    );
    const user = result.rows[0];
    return {
      first_name: user.first_name,
      last_name: user.last_name,
      join_at: user.join_at,
      last_login_at: user.last_login_at,
      phone: user.phone,
      username: user.username,
    };
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id, m.body, m.sent_at, m.read_at, u.username, u.first_name, u.last_name, u.phone
        FROM messages as m
        JOIN users as u
          ON (m.to_username = u.username)
        WHERE (m.from_username = $1)`,
      [username]
    );

    const messagesFrom = result.rows.map((msg) => ({
      id: msg.id,
      body: msg.body,
      sent_at: msg.sent_at,
      read_at: msg.read_at,
      to_user: {
        username: msg.username,
        first_name: msg.first_name,
        last_name: msg.last_name,
        phone: msg.phone,
      },
    }));
    return messagesFrom;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const result = await db.query(
      `SELECT *
        FROM messages as m
          JOIN users as u
            ON m.from_username=u.username
        WHERE (to_username = $1)`,
      [username]
    );
    const messagesTo = result.rows.map((msg) => ({
      id: msg.id,
      body: msg.body,
      sent_at: msg.sent_at,
      read_at: msg.read_at,
      from_user: {
        username: msg.username,
        first_name: msg.first_name,
        last_name: msg.last_name,
        phone: msg.phone,
      },
    }));
    return messagesTo;
  }
}

module.exports = User;
