# Government Complaint Portal

A modern web application for citizens to file and track complaints, and for government officials to manage and respond to them efficiently.

## Features

- *User Authentication*
  - Citizen registration and login
  - Admin and Officer accounts
  - Secure password hashing
  - Session management

- *Complaint Management*
  - File new complaints with categorisation
  - Prioritise complaints based on urgency
  - Track complaint status
  - View complaint history
  - Add comments and updates

- *Admin Dashboard*
  - Manage user accounts
  - Create officer accounts
  - Monitor all complaints
  - Update complaint statuses

- *Modern UI*
  - Responsive design using Tailwind CSS
  - Clean and intuitive interface

## Tech Stack

- *Backend*
  - Node.js
  - Express.js
  - MongoDB
  - JWT Authentication
  - Bcrypt for password hashing

- *Frontend*
  - EJS Templates
  - Tailwind CSS
  - Express EJS Layouts

- *AI Integration*
  - Google Gemini AI for chat support and complaint categorisation

## Prerequisites

- Node.js (v14 or higher)
- MongoDB
- Google Gemini API key

## Installation

1. Clone the repository:
bash
git clone <repository-url>
cd government-complaint-portal


2. Install dependencies:
bash
npm install


3. Create a .env file in the root directory:
env
GEMINI_API_KEY=your_gemini_api_key


4. Start MongoDB:
bash
mongod


5. Run the application:
bash
node app.js


The application will be available at http://localhost:3000

## Default Accounts

- *Admin*
  - Email: admin@example.com
  - Password: admin123

- *Citizen*
  - Register through the signup page


## API Endpoints

- POST /api/chat - AI chat endpoint
- POST /complaints - File a new complaint
- GET /my-complaints - View user's complaints
- POST /update-complaint-status - Update complaint status (Admin/Officer only)

## Security Features

- Password hashing with bcrypt
- JWT-based authentication
- Role-based access control
- Secure cookie handling
- Input validation

## Contributing

1. Fork the repository
2. Create your feature branch (git checkout -b feature/AmazingFeature)
3. Commit your changes (git commit -m 'Add some AmazingFeature')
4. Push to the branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

## License

This project is licensed under the ISC License.

## Support

For support, please open an issue in the GitHub repository or contact the project maintainers.