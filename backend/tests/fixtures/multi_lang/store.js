// Synthetic Express + Sequelize app used only as scanner input.

const express = require("express");
const { DataTypes } = require("sequelize");

const app = express();

const Subscriber = sequelize.define(
  "Subscriber",
  {
    email_address: { type: DataTypes.STRING, allowNull: false },
    aadhaar_number: { type: DataTypes.STRING, allowNull: false },
    pan_number: { type: encryptedField(DataTypes.STRING), allowNull: false },
    session_expires_at: { type: DataTypes.DATE },
  },
  { tableName: "subscribers" }
);

app.post("/subscribers", (req, res) => {
  console.log(`registering ${req.body.email_address}`);
  res.sendStatus(201);
});

app.get("/subscribers/:subscriberId", requireAuth, async (req, res) => {
  const row = await Subscriber.findOne({ where: { id: req.params.subscriberId } });
  res.json(row);
});

module.exports = { app, Subscriber };
