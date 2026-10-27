# FUELX NEXUS Mobile App (Expo starter)
Run `npm install` then `npx expo start`.
API URL in `App.js` defaults to `http://10.0.2.2:3000` for Android emulator. On a physical phone replace with the laptop's LAN IPv4 address; both devices must share Wi-Fi and firewall must allow port 3000.
The mobile app shares the backend auth and order APIs. It is a starter, and requires device testing. For local OTP demo, configure `DEV_OTP_MODE=true` in the backend `.env` and read OTP from the terminal.
