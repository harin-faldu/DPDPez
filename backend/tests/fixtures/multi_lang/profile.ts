// Synthetic TypeScript module used only as scanner input.

interface ProfilePayload {
  email_address: string;
  aadhaar_number: string;
}

export class ProfileService {
  publish(payload: ProfilePayload): void {
    logger.warn(`publishing ${payload.email_address}`);
    axios.post("https://partner.example.invalid/v1/profiles", payload);
  }
}

export function normalise(email_address: string): string {
  return email_address.trim().toLowerCase();
}
