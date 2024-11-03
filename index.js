const express = require('express');
const app = express();
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'nosacoasjcw80wcjwcnkjnoajc0wcnasckjasci0cicnoi';

// Middleware to parse JSON bodies
app.use(express.json());

let db;

function handleDisconnect() {
    db = mysql.createConnection({
        user: 'root',
        host: 'dev.cvwa2eocu5rr.ap-south-1.rds.amazonaws.com',
        password: 'Varanasi123#',
        database: 'dev'
    });

    db.connect((err) => {
        if (err) {
            console.log('Error connecting to db:', err);
            setTimeout(handleDisconnect, 2000); // Try to reconnect after 2 seconds
        } else {
            console.log('Connected to database');
        }
    });

    db.on('error', (err) => {
        console.log('Database error:', err);
        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            handleDisconnect(); // Reconnect on connection lost
        } else {
            throw err; // For other errors
        }
    });
}

handleDisconnect();


// Route to select all countries
app.post('/getProfile', (req, res) => {
    const { phone_number } = req.body; // Extract phone_number from request body

    if (!phone_number) {
        return res.status(400).send('Phone number is required');
    }

    const query = 'SELECT * FROM user_profile WHERE phone_number = ?';
    
    db.query(query, [phone_number], (err, result) => {
        if (err) {
            console.log(err);
            return res.status(500).send('Error occurred during the query.');
        }

        if (result.length > 0) {
            res.json(result); // Send the result if user is found
        } else {
            res.status(404).send('User not found'); // Handle case where no user is found
        }
    });
});

<<<<<<< HEAD

function isRegistered(phone_number) {
    return new Promise((resolve, reject) => {
        const query = 'SELECT * FROM user_profile WHERE phone_number = ?';
        
        db.query(query, [phone_number], (err, result) => {
            if (err) {
                return reject(err);
            }
            if (result.length > 0) {
                resolve(true);  // User exists
            } else {
                resolve(false); // User doesn't exist
            }
        });
    });
}

=======
function isRegistered(phone_number) {
    return new Promise((resolve, reject) => {
        const query = 'SELECT * FROM user_profile WHERE phone_number = ?';
        
        db.query(query, [phone_number], (err, result) => {
            if (err) {
                return reject(err);
            }
            if (result.length > 0) {
                resolve(true);  // User exists
            } else {
                resolve(false); // User doesn't exist
            }
        });
    });
}

>>>>>>> bcfdb076ee81ce3255f6c4777c7c17057f55dcdd
app.get('/isUserRegistered', (req, res) => {
    const { phone_number } = req.query; // Use req.query for GET request

    if (!phone_number) {
        return res.status(400).send('Phone number cannot be empty');
    }

    const query = 'SELECT * FROM user_profile WHERE phone_number = ?';
    
    db.query(query, [phone_number], (err, result) => {
        if (err) {
            console.error('Error executing query', err);
            return res.status(500).send('Internal server error');
        }

        if (result.length > 0) {
            return res.status(400).json({ userAlreadyExists: true});
        } else {
            return res.status(200).json({ userAlreadyExists: false });
        }
    });
});



app.post('/signup', async (req, res) => {
    const { phone_number, first_name, last_name, secondary_number, primary_email, secondary_email, company, designation, company_start_date, company_end_date, profile_description, mac_id, linkedin_profile_link } = req.body;

    try {
        // Check if the user is already registered
        const userExists = await isRegistered(phone_number);

        if (userExists) {
            // If user already exists, send a response without making a DB entry
            return res.status(400).json({ message: 'User Already Exists With This Phone Number' });
        }

        // Proceed with user registration if the user doesn't exist
        const query = 'INSERT INTO user_profile (phone_number, first_name, last_name, secondary_number, primary_email, secondary_email, company, designation, company_start_date, company_end_date, profile_description, mac_id, linkedin_profile_link) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE mac_id = ?';
        const values = [phone_number, first_name, last_name, secondary_number, primary_email, secondary_email, company, designation, company_start_date, company_end_date, profile_description, mac_id, linkedin_profile_link, mac_id];

        db.query(query, values, (err, result) => {
            if (err) {
                console.log(err);
                return res.status(500).send('Error occurred during the query.');
            }

            // Respond after successful registration
            res.status(200).send('');
        });

    } catch (err) {
        console.error('Error checking user registration', err);
        res.status(500).send('Internal server error');
    }
});

// Send OTP endpoint
app.post('/send-otp', (req, res) => {
  const { phoneNumber } = req.body;

  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit OTP

  // Insert phone number and OTP into the database, update OTP if phone number exists
  const otpquery = 'INSERT INTO authentication (phone_number, otp) VALUES (?, ?) ON DUPLICATE KEY UPDATE otp = ?';
  const otpvalues = [phoneNumber, otp, otp]; // Providing OTP for both insert and update

  db.query(otpquery, otpvalues, (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database query error' });
    }

    // In production, you should not send the OTP back in the response
    res.json({ message: `OTP sent to ${phoneNumber}`, otp });

    // In development, you can include OTP in the response for testing purposes
    // res.json({ message: `OTP sent to ${phoneNumber}`, otp });
  });
});

  
  // Verify OTP endpoint
  const authenticateUser = (phone_number, res) => {
    // Query to check phone_number only
    const query = 'SELECT * FROM user_profile WHERE phone_number = ?';

    db.query(query, [phone_number], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error occurred during the query.' });
        }

        // Check if a user is found
        if (result.length > 0) {
            const user = result[0]; // Assuming only one user is returned

            // Generate a JWT token
            const token = jwt.sign(
                {
                    phone_number: user.phone_number
                },
                JWT_SECRET // Secret key
            );

            // Query to insert or update the auth_key table
            const authKeyQuery = 'INSERT INTO auth_key (phone_number, auth_key) VALUES (?, ?) ON DUPLICATE KEY UPDATE auth_key = ?';
            const authKeyValues = [phone_number, token, token]; // Values to insert or update

            // Insert or update the token in the auth_key table
            db.query(authKeyQuery, authKeyValues, (authErr) => {
                if (authErr) {
                    console.error('Error inserting or updating auth_key', authErr);
                    return res.status(500).json({ error: 'Error occurred while saving auth token.' });
                }

                // Send the token and user profile data back
                res.json({
                    message: 'User authenticated successfully',
                    token, // Auth token
                    profile: user // Optional: send back the user profile
                });
            });
        } else {
            // No user found
            res.status(404).json({ message: 'User not found' });
        }
    });
};

app.post('/login-verify-otp', async (req, res) => {
    const { phoneNumber, otp } = req.body;

    if (!phoneNumber || !otp) {
        return res.status(400).json({ error: 'Phone number and OTP are required' });
    }

    // Query the database to verify the OTP
    const otpQuery = 'SELECT * FROM authentication WHERE phone_number = ? AND otp = ?';
    const otpValues = [phoneNumber, otp];

    db.query(otpQuery, otpValues, async (err, result) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ error: 'Database query error' });
        }

        if (result.length > 0) {
            // OTP matches
            // Check if the user is registered
            try {
                const registered = await isRegistered(phoneNumber);
                if (registered) {
                    // Delete the OTP entry
                    const deleteQuery = 'DELETE FROM authentication WHERE phone_number = ?';
                    db.query(deleteQuery, [phoneNumber], (err) => {
                        if (err) {
                            console.error('Error deleting OTP:', err);
                        }
                    });

                    // Authenticate the user and send response with profile and token
                    authenticateUser(phoneNumber, res);
                } else {
                    return res.status(404).json({ message: 'User not found' });
                }
            } catch (error) {
                console.error('Error fetching user profile:', error);
                return res.status(500).json({ error: 'Error fetching user profile' });
            }
        } else {
            // OTP doesn't match
            return res.status(400).json({ error: 'Invalid OTP or phone number' });
        }
    });
});

app.post('/getUserList', (req, res) => {
    const macIds = req.body.map((item) => item.mac_id);

    if (!macIds || macIds.length === 0) {
        return res.status(400).json({ error: 'mac_id list cannot be empty' });
    }

    // Construct the SQL query to fetch user profiles based on mac_ids
    const query = `SELECT * FROM user_profile WHERE mac_id IN (?)`;

    db.query(query, [macIds], (err, results) => {
        if (err) {
            console.error('Error executing query:', err);
            return res.status(500).json({ error: 'Database query error' });
        }

        // Wrap each result in an object with a 'profile' key
        const response = results.map((profile) => ({ profile }));

        res.json(response);
    });
});

app.post('/getProfile', (req, res) => {
    const { phone_number } = req.body; // Extract phone_number from request body

    if (!phone_number) {
        return res.status(400).send('Phone number is required');
    }

    const query = 'SELECT * FROM user_profile WHERE phone_number = ?';

    db.query(query, [phone_number], (err, result) => {
        if (err) {
            console.log(err);
            return res.status(500).send('Error occurred during the query.');
        }

        if (result.length > 0) {
            res.json(result[0]); // Send the first result if user is found
        } else {
            res.status(404).send('User not found'); // Handle case where no user is found
        }
    });
});

app.post('/getUserList', (req, res) => {
    const macIds = req.body.map((item) => item.mac_id);

    if (!macIds || macIds.length === 0) {
        return res.status(400).json({ error: 'mac_id list cannot be empty' });
    }

    // Construct the SQL query to fetch user profiles based on mac_ids
    const query = `SELECT * FROM user_profile WHERE mac_id IN (?)`;

    db.query(query, [macIds], (err, results) => {
        if (err) {
            console.error('Error executing query:', err);
            return res.status(500).json({ error: 'Database query error' });
        }

        // Wrap each result in an object with a 'profile' key
        const response = results.map((profile) => ({ profile }));

        res.json(response);
    });
});

app.post('/login-send-otp', (req, res) => {
    const { phoneNumber } = req.body;
  
    if (!phoneNumber) {
      return res.status(400).json({ error: 'Phone number is required' });
    }
  
    const otp = Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit OTP
  
    // Check if the phone number exists in the user_profile table
    const checkUserQuery = 'SELECT phone_number FROM user_profile WHERE phone_number = ?';
    
    db.query(checkUserQuery, [phoneNumber], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Database query error' });
      }
  
      if (result.length === 0) {
        // If the phone number does not exist in the user_profile table, send an error response
        return res.status(404).json({ error: 'Phone number not found' });
      }
  
      // If phone number exists, proceed to insert/update OTP in authentication table
      const otpQuery = `
        INSERT INTO authentication (phone_number, otp)
        VALUES (?, ?)
        ON DUPLICATE KEY UPDATE otp = ?
      `;
      const otpValues = [phoneNumber, otp, otp];
  
      db.query(otpQuery, otpValues, (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Database query error' });
        }
  
        // In production, avoid sending the OTP in the response
        res.json({ message: `OTP sent to ${phoneNumber}`, otp });
  
        // In development, you might include the OTP for testing purposes
        // res.json({ message: `OTP sent to ${phoneNumber}`, otp });
      });
    });
  });
  

app.listen(3001, () => {
    console.log('Server Running');
});
