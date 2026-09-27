// Synthetic Mongoose schema used only as scanner input.

const profileSchema = new mongoose.Schema(
  {
    email_address: { type: String, required: true },
    aadhaar_number: { type: String },
    pan_number: { type: String, get: decryptField },
    token_ttl: { type: Number },
  },
  { collection: "profiles" }
);

module.exports = profileSchema;
