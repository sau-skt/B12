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

app.put('/updateProfile', (req, res) => {
    const {
        phone_number,
        first_name,
        last_name,
        secondary_number,
        primary_email,
        secondary_email,
        company,
        designation,
        company_start_date,
        company_end_date,
        profile_description,
        mac_id,
        linkedin_profile_link
    } = req.body;

    if (!phone_number) {
        return res.status(400).json({ error: 'Phone number is required to update profile.' });
    }

    // Create an updateFields object with only the provided fields
    const updateFields = {};
    if (first_name) updateFields.first_name = first_name;
    if (last_name) updateFields.last_name = last_name;
    if (secondary_number) updateFields.secondary_number = secondary_number;
    if (primary_email) updateFields.primary_email = primary_email;
    if (secondary_email) updateFields.secondary_email = secondary_email;
    if (company) updateFields.company = company;
    if (designation) updateFields.designation = designation;
    if (company_start_date) updateFields.company_start_date = company_start_date;
    if (company_end_date) updateFields.company_end_date = company_end_date;
    if (profile_description) updateFields.profile_description = profile_description;
    if (mac_id) updateFields.mac_id = mac_id;
    if (linkedin_profile_link) updateFields.linkedin_profile_link = linkedin_profile_link;

    // If no fields to update are provided
    if (Object.keys(updateFields).length === 0) {
        return res.status(400).json({ error: 'No fields provided for update.' });
    }

    // Construct the dynamic query
    const updateKeys = Object.keys(updateFields).map(key => `${key} = ?`).join(', ');
    const updateValues = Object.values(updateFields);

    // Final SQL query and values
    const query = `UPDATE user_profile SET ${updateKeys} WHERE phone_number = ?`;
    const values = [...updateValues, phone_number];

    db.query(query, values, (err, result) => {
        if (err) {
            console.error('Error updating profile:', err);
            return res.status(500).json({ error: 'Database query error while updating profile.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        res.json({ message: 'Profile updated successfully.' });
    });
});

app.post('/updateSelection', (req, res) => {
    const token = req.headers['authorization']; // Extract token from headers

    if (!token) {
        return res.status(401).json({ error: 'Authorization token is required' });
    }

    // Query to find phone_number associated with the given token
    const authKeyQuery = 'SELECT phone_number FROM auth_key WHERE auth_key = ?';

    db.query(authKeyQuery, [token], (authErr, authResult) => {
        if (authErr) {
            console.error('Error fetching auth key:', authErr);
            return res.status(500).json({ error: 'Database query error while fetching auth key' });
        }

        if (authResult.length === 0) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }

        const from_phone_number = authResult[0].phone_number; // Retrieve phone_number from query result

        // Extract to_phone_number and status from request body
        const { to_phone_number, status } = req.body;

        if (!to_phone_number || !status) {
            return res.status(400).json({ error: 'to_phone_number and status are required' });
        }

        // Query to insert or update the selection data if both phone numbers match
        const insertQuery = `
            INSERT INTO user_selection (from_phone_number, to_phone_number, status)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE status = ?
        `;
        const insertValues = [from_phone_number, to_phone_number, status, status];

        db.query(insertQuery, insertValues, (insertErr, insertResult) => {
            if (insertErr) {
                console.error('Error inserting or updating selection data:', insertErr);
                return res.status(500).json({ error: 'Database query error while inserting or updating selection data' });
            }

            res.json({ message: 'Selection data inserted or updated successfully' });
        });
    });
});




// Route to select all countries
app.post('/getProfile', (req, res) => {
    const token = req.headers['authorization']; // Extract token from headers

    if (!token) {
        return res.status(401).json({ error: 'Authorization token is required' });
    }

    // Query to find phone_number associated with the given token
    const authKeyQuery = 'SELECT phone_number FROM auth_key WHERE auth_key = ?';

    db.query(authKeyQuery, [token], (authErr, authResult) => {
        if (authErr) {
            console.error('Error fetching auth key:', authErr);
            return res.status(500).json({ error: 'Database query error while fetching auth key' });
        }

        if (authResult.length === 0) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }

        const phone_number = authResult[0].phone_number; // Retrieve phone_number from query result

        // Proceed to fetch user profile using the retrieved phone_number
        const profileQuery = 'SELECT * FROM user_profile WHERE phone_number = ?';

        db.query(profileQuery, [phone_number], (profileErr, profileResult) => {
            if (profileErr) {
                console.error('Error fetching profile:', profileErr);
                return res.status(500).json({ error: 'Database query error while fetching profile' });
            }

            if (profileResult.length > 0) {
                res.json(profileResult[0]); // Send the user profile if found
            } else {
                res.status(404).json({ error: 'User not found' }); // Handle case where no user is found
            }
        });
    });
});



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
            return res.status(400).json({ userAlreadyExists: true });
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
    const token = req.headers['authorization']; // Extract token from headers

    if (!token) {
        return res.status(401).json({ error: 'Authorization token is required' });
    }

    // Query to find phone_number associated with the given token
    const authKeyQuery = 'SELECT phone_number FROM auth_key WHERE auth_key = ?';

    db.query(authKeyQuery, [token], (authErr, authResult) => {
        if (authErr) {
            console.error('Error fetching auth key:', authErr);
            return res.status(500).json({ error: 'Database query error while fetching auth key' });
        }

        if (authResult.length === 0) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }

        const phone_number = authResult[0].phone_number; // Retrieve phone_number from query result
        const macIds = req.body.map((item) => item.mac_id);

        if (!macIds || macIds.length === 0) {
            return res.status(400).json({ error: 'mac_id list cannot be empty' });
        }

        // Query to fetch invite_sent status
        const queryInviteSent = `
            SELECT 
                user_profile.*, 
                user_selection.status AS invite_sent 
            FROM 
                user_profile 
            LEFT JOIN 
                user_selection 
            ON 
                user_profile.phone_number = user_selection.to_phone_number 
                AND user_selection.from_phone_number = ? 
            WHERE 
                user_profile.mac_id IN (?)
        `;

        // Query to fetch invite_received status
        const queryInviteReceived = `
            SELECT 
                user_profile.phone_number, 
                user_selection.status AS invite_received 
            FROM 
                user_profile 
            LEFT JOIN 
                user_selection 
            ON 
                user_profile.phone_number = user_selection.from_phone_number 
                AND user_selection.to_phone_number = ? 
            WHERE 
                user_profile.mac_id IN (?)
        `;

        // Execute both queries
        db.query(queryInviteSent, [phone_number, macIds], (errSent, sentResults) => {
            if (errSent) {
                console.error('Error executing query for invite_sent:', errSent);
                return res.status(500).json({ error: 'Database query error for invite_sent' });
            }

            db.query(queryInviteReceived, [phone_number, macIds], (errReceived, receivedResults) => {
                if (errReceived) {
                    console.error('Error executing query for invite_received:', errReceived);
                    return res.status(500).json({ error: 'Database query error for invite_received' });
                }

                // Combine results based on phone_number
                const receivedMap = Object.fromEntries(
                    receivedResults.map((item) => [item.phone_number, item.invite_received || "no-comm"])
                );

                const response = sentResults.map((profile) => ({
                    profile: {
                        phone_number: profile.phone_number,
                        first_name: profile.first_name,
                        last_name: profile.last_name,
                        secondary_number: profile.secondary_number,
                        primary_email: profile.primary_email,
                        secondary_email: profile.secondary_email,
                        company: profile.company,
                        designation: profile.designation,
                        company_start_date: profile.company_start_date,
                        company_end_date: profile.company_end_date,
                        profile_description: profile.profile_description,
                        mac_id: profile.mac_id,
                        linkedin_profile_link: profile.linkedin_profile_link
                    },
                    invite_sent: profile.invite_sent || "no-comm",
                    invite_received: receivedMap[profile.phone_number] || "no-comm" // Set default if invite_received is null
                }));

                res.json(response);
            });
        });
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
