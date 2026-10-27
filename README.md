# FUELX NEXUS — Rebuild

A rebuilt, separate-page customer website for a fuel-delivery business. The app has distinct routes for Home, Services, Plans, Checkout, About, Contact, Account, FAQ, Terms and Privacy.

## Run locally (Windows)
1. Install Node.js 18+.
2. Extract this ZIP.
3. Open Command Prompt inside the extracted `FUELX_NEXUS_REBUILT` folder.
4. Run `npm install`
5. Run `npm start`
6. Open `http://localhost:3000`

## What works in this build
- Separate URL routes and navigation.
- Preview login / account creation, stored in the local JSON database.
- Service order form and order history.
- Plan catalogue, plan selection, and a test checkout flow.
- Test-only payment success/failure recording.
- Profile editing and saved delivery addresses.
- Contact form.

## Important production requirements
This is a functional local prototype, **not ready to accept real customer money or dispatch fuel**. Login is preview-only and does not verify email/password. Payments are explicitly TEST ONLY; they do not charge a card, UPI account, or bank account. Before launch, integrate a real identity/authentication provider, Razorpay or another payment gateway using server-side order creation and verified webhooks, production database, HTTPS hosting, delivery operations, tax/invoice rules, and legal/safety/compliance requirements. Never store raw card numbers or CVVs in this app. Plan prices and fuel prices are sample configuration and must be confirmed before publishing.

## Membership card UI
The account overview and My Subscription page show a visual membership card with plan name, monthly price, status, payment status, member date and short member ID. This is a UI card only, not a bank/payment card.

## Subscription card at checkout
Active subscription members can choose `Subscription card` as a fuel-order payment method. A test balance can be added from Account → My subscription. The balance is prototype-only and does not represent real stored funds; production must integrate a payment provider and credit funds only after verified payment webhooks.


## Secure email / phone OTP authentication

This version replaces preview sign-in with OTP verification. User identity, OTP challenges and sessions are stored in SQLite (`auth.sqlite`). The rest of the prototype's order/subscription data currently remains in the local `data.json` store; production should migrate all business records into a production database too.

### Email OTP setup (Gmail example)
1. Copy `.env.example` to `.env`.
2. Enable 2-Step Verification on the Gmail account used by the project.
3. Generate a Gmail App Password. Do not use your normal Gmail password.
4. Fill in `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM` in `.env`.
5. Keep `.env` private and never commit it to GitHub.
6. Run `npm install` and `npm start`, then open `http://localhost:3000`.

### Phone OTP setup
Create a Twilio account, configure a permitted sender/phone number, then fill in `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_FROM`. Phone numbers must be in international format, e.g. `+919876543210`. SMS delivery and costs depend on the provider account, destination and sender setup.

### Authentication behavior
- New customer selects **Create account**, enters a name and email or phone, receives a one-time code, then verifies it.
- Existing customer selects **Login**, enters the registered email or phone, receives a one-time code, then verifies it.
- OTP expires after 5 minutes, and verification attempts are limited.
- A successful verification creates a server-side session token; the customer name appears in the header.
- The first login will not work until the selected OTP provider is configured. This is intentional; the site must not pretend to send OTPs.

### Before production
Use HTTPS, secure cookie-based sessions or a carefully reviewed token strategy, CSRF protections where applicable, verified payment webhooks, database backups/migrations, monitoring, abuse controls, privacy/retention policies, and a production database for all customer/order/subscription data. Never collect or store raw card numbers or CVVs.


## Troubleshooting: page stuck on Loading
- Start the app using `npm start` and keep the terminal open.
- Visit `http://localhost:3000` (do not open `index.html` directly).
- Hard refresh with `Ctrl + Shift + R`.
- If a render error occurs, this version displays the error message on the page instead of staying on the loading placeholder.
- If an older preview session was saved in the browser, use Account → Sign out. If the account link is stale, clear site data for localhost and reload.


## Updated registration and login flow
- New customer chooses Register, selects email or phone, enters name and a password (minimum 8 characters), and verifies the one-time OTP. The account is created only after successful OTP verification.
- Existing customer chooses Login, selects email or phone, and signs in with the password created during registration. OTP is not sent on every login.
- Passwords are stored as salted scrypt hashes, not plaintext.
- Email registration OTP requires SMTP variables in `.env`; phone registration OTP requires Twilio variables in `.env`. Configure the relevant provider once on the server, not for each customer.


## Delivery scheduling, member discount and cancellation
- Active subscription: server applies a 10% discount to the fuel subtotal.
- Emergency request: marked as a 10-minute target, pending nearby pump confirmation; it is not a guaranteed delivery SLA.
- Scheduled delivery: date/time must be in the next 7 days.
- Cancellation endpoint: before dispatch no fee in the prototype; after eligible dispatch/confirmation status, fee estimate is 5% of order total, minimum ₹50. Confirm final policy with a lawyer/operator before launch.
- Indicative Satara rates coded for demo (27 Oct 2026): petrol ₹112.39/L, diesel ₹99.05/L, premium fuel ₹117.39/L (premium is an illustrative surcharge, not an official retail grade quote). These are not a live price feed and must be refreshed/verified for the service city before public launch.
- Delivery/pump availability and service fees are not yet connected to a real dispatch network.


## Account access (current demo flow)
- New customers choose **Create account**, select Email or Phone, enter their name, identifier and a password (minimum 8 characters), then press **Create account**. The account is created immediately; no OTP is sent.
- Existing customers choose **Login** and use the same email/phone identifier and password.
- Email/phone ownership is **not verified** in this demo. Before a real public launch, add a secure verification/recovery process, HTTPS, and appropriate account-abuse protections.
- Authentication uses a local SQLite database (`auth.sqlite`). Keep the database file private and back it up for demos.
