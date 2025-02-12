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

app.post('/sendMessage', (req, res) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ error: 'Authorization token is required' });
    }

    const authKeyQuery = 'SELECT phone_number FROM auth_key WHERE auth_key = ?';

    db.query(authKeyQuery, [token], (authErr, authResult) => {
        if (authErr) {
            console.error('Error fetching auth key:', authErr);
            return res.status(500).json({ error: 'Database query error while fetching auth key' });
        }

        if (authResult.length === 0) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }

        const senderPhoneNumber = authResult[0].phone_number;
        const { message, timestamp, phone } = req.body;

        if (!message || !timestamp || !phone) {
            return res.status(400).json({ error: 'Message, timestamp, and receiver phone number are required' });
        }

        // Convert the timestamp to a MySQL-compatible DATETIME format
        const datetime = new Date(timestamp * 1000).toISOString().slice(0, 19).replace('T', ' ');

        const insertMessageQuery = `
            INSERT INTO user_chat (sender_phone_number, receiver_phone_number, message, created_at)
            VALUES (?, ?, ?, ?)
        `;

        db.query(insertMessageQuery, [senderPhoneNumber, phone, message, datetime], (insertErr, insertResult) => {
            if (insertErr) {
                console.error('Error inserting message:', insertErr);
                return res.status(500).json({ error: 'Database query error while inserting message' });
            }

            res.status(200).json({ success: true, message: 'Message sent successfully' });
        });
    });
});

app.post('/fetchAllMessages', express.json(), (req, res) => {
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

        const phone_number = authResult[0].phone_number; // Retrieve authenticated user's phone number
        const { receiverPhoneNumber } = req.body; // Retrieve receiver's phone number from the request body

        if (!receiverPhoneNumber) {
            return res.status(400).json({ error: 'Receiver phone number is required' });
        }

        // Query to fetch all messages between the authenticated user and the receiver, sorted by created_at
        const fetchMessagesQuery = `
            SELECT * 
            FROM user_chat
            WHERE (sender_phone_number = ? AND receiver_phone_number = ?)
               OR (sender_phone_number = ? AND receiver_phone_number = ?)
            ORDER BY created_at ASC
        `;

        db.query(fetchMessagesQuery, [phone_number, receiverPhoneNumber, receiverPhoneNumber, phone_number], (fetchErr, messages) => {
            if (fetchErr) {
                console.error('Error fetching messages:', fetchErr);
                return res.status(500).json({ error: 'Database query error while fetching messages' });
            }

            res.status(200).json({  messages });
        });
    });
});

app.post('/createNewEvent', (req, res) => {
    const token = req.headers['authorization']; // Extract token from headers

    if (!token) {
        return res.status(401).json({ error: 'Authorization token is required' });
    }

    const { event_name, timestamp } = req.body;

    // Validate the event_name field
    if (!event_name || typeof event_name !== 'string' || event_name.trim() === '') {
        return res.status(400).json({ error: 'A valid event name is required' });
    }

    // Validate the timestamp field
    if (!timestamp || typeof timestamp !== 'number' || timestamp <= 0) {
        return res.status(400).json({ error: 'A valid timestamp is required' });
    }

    // Convert Unix timestamp (in seconds) to ISO 8601 datetime format for SQL
    const formattedTimestamp = new Date(timestamp * 1000).toISOString().slice(0, 19).replace('T', ' ');

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

        // Insert the event name and timestamp into the user_event table
        const insertEventQuery = 'INSERT INTO user_event (event_name, created_at) VALUES (?, ?)';

        db.query(insertEventQuery, [event_name, formattedTimestamp], (insertErr, insertResult) => {
            if (insertErr) {
                console.error('Error inserting event:', insertErr);
                return res.status(500).json({ error: 'Database query error while inserting event' });
            }

            const event_id = insertResult.insertId; // Get the event_id of the newly inserted event

            // Insert the data into the user_list table
            const insertUserListQuery = `
                INSERT INTO user_list (primary_id, secondary_id, phone_number)
                VALUES (?, ?, ?)
            `;

            db.query(insertUserListQuery, [event_id, event_id, phone_number], (listInsertErr) => {
                if (listInsertErr) {
                    console.error('Error inserting into user_list:', listInsertErr);
                    return res.status(500).json({ error: 'Database query error while inserting into user_list' });
                }

                // Respond with success
                res.status(200).json({
                    success: true,
                    message: 'Event created and user_list updated successfully',
                    event_id: event_id,
                    phone_number: phone_number,
                });
            });
        });
    });
});

app.post('/joinEvent', (req, res) => {
    const token = req.headers['authorization']; // Extract token from headers

    if (!token) {
        return res.status(401).json({ error: 'Authorization token is required' });
    }

    const { event_id } = req.body;

    // Validate the event_id field
    if (!event_id || typeof event_id !== 'string' || event_id.trim() === '') {
        return res.status(400).json({ error: 'A valid event ID is required' });
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

        // Query to insert a new entry into the user_list table
        const insertQuery = 'INSERT INTO user_list (primary_id, secondary_id, phone_number) VALUES (?, ?, ?)';

        db.query(insertQuery, [event_id, event_id, phone_number], (insertErr) => {
            if (insertErr) {
                console.error('Error inserting into user_list:', insertErr);
                return res.status(500).json({ error: 'Database query error while inserting into user_list' });
            }

            // Query to retrieve all phone numbers associated with the event_id
            const fetchPhoneNumbersQuery = 'SELECT phone_number FROM user_list WHERE primary_id = ?';

            db.query(fetchPhoneNumbersQuery, [event_id], (fetchErr, fetchResult) => {
                if (fetchErr) {
                    console.error('Error fetching phone numbers:', fetchErr);
                    return res.status(500).json({ error: 'Database query error while fetching phone numbers' });
                }

                const phoneNumbers = fetchResult.map(row => row.phone_number);

                // Query to fetch profiles for all phone numbers
                const fetchProfilesQuery = `
                    SELECT * FROM user_profile WHERE phone_number IN (?)
                `;

                db.query(fetchProfilesQuery, [phoneNumbers], (profileErr, profileResult) => {
                    if (profileErr) {
                        console.error('Error fetching profiles:', profileErr);
                        return res.status(500).json({ error: 'Database query error while fetching profiles' });
                    }

                    // Structure the response
                    const response = profileResult.map(profile => ({
                        profile
                    }));

                    // Send the response
                    return res.status(200).json(response);
                });
            });
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
    const getISTTimestamp = () => new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' });

    console.log(`[${getISTTimestamp()}] Request Body:`, req.body);

    const { phone_number, first_name, last_name, secondary_number, primary_email, secondary_email, company, designation, company_start_date, company_end_date, profile_description, mac_id, linkedin_profile_link } = req.body;

    try {
        // Check if the user is already registered
        const userExists = await isRegistered(phone_number);

        if (userExists) {
            // If user already exists, send a response without making a DB entry
            console.log(`[${getISTTimestamp()}] Response Body: User Already Exists`);
            return res.status(400).json({ message: 'User Already Exists With This Phone Number' });
        }

        // Proceed with user registration if the user doesn't exist
        const query = `INSERT INTO user_profile 
            (phone_number, first_name, last_name, secondary_number, primary_email, secondary_email, company, designation, company_start_date, company_end_date, profile_description, mac_id, linkedin_profile_link) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
            ON DUPLICATE KEY UPDATE mac_id = ?`;

        const values = [phone_number, first_name, last_name, secondary_number, primary_email, secondary_email, company, designation, company_start_date, company_end_date, profile_description, mac_id, linkedin_profile_link, mac_id];

        db.query(query, values, (err, result) => {
            if (err) {
                console.log(`[${getISTTimestamp()}] Error:`, err);
                return res.status(500).send('Error occurred during the query.');
            }

            // Respond after successful registration
            console.log(`[${getISTTimestamp()}] Response Body: User is Registered Successfully`);
            res.status(200).send('');
        });

    } catch (err) {
        console.error(`[${getISTTimestamp()}] Error checking user registration:`, err);
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

app.post('/verify-otp', async (req, res) => {
    console.log('Request Body:', req.body); // Log the request body

    const { phoneNumber, otp } = req.body;

    if (!phoneNumber || !otp) {
        const errorResponse = { error: 'Phone number and OTP are required' };
        console.error('Response:', errorResponse);
        return res.status(400).json(errorResponse);
    }

    // Query the database to verify the OTP
    const otpQuery = 'SELECT * FROM authentication WHERE phone_number = ? AND otp = ?';
    const otpValues = [phoneNumber, otp];

    console.log(`Verifying OTP for phone number: ${phoneNumber}, OTP: ${otp}`);

    db.query(otpQuery, otpValues, async (err, result) => {
        if (err) {
            console.error('Database Query Error:', err);
            const errorResponse = { error: 'Database query error' };
            console.error('Response:', errorResponse);
            return res.status(500).json(errorResponse);
        }

        if (result.length > 0) {
            console.log(`OTP verified successfully for phone number: ${phoneNumber}`);
            const successResponse = { message: 'OTP verified successfully' };
            console.log('Response:', successResponse);
            return res.json(successResponse);
        } else {
            console.warn(`Invalid OTP or phone number: ${phoneNumber}`);
            const errorResponse = { error: 'Invalid OTP or phone number' };
            console.warn('Response:', errorResponse);
            return res.status(400).json(errorResponse);
        }
    });
});

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

app.post('/getEventList', (req, res) => {
    const authKeyQuery = 'SELECT phone_number FROM auth_key WHERE auth_key = ?';
    const token = req.headers.authorization; // Assuming token is passed in the headers

    // Validate token
    db.query(authKeyQuery, [token], (authErr, authResult) => {
        if (authErr) {
            console.error('Error fetching auth key:', authErr);
            return res.status(500).json({ error: 'Database query error while fetching auth key' });
        }

        if (authResult.length === 0) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }

        const phone_number = authResult[0].phone_number; // Phone number associated with token
        const macIds = req.body.map((item) => item.mac_id);

        if (!macIds || macIds.length === 0) {
            return res.status(400).json({ error: 'mac_id list cannot be empty' });
        }

        // Get phone_numbers from user_profile table using mac_id
        const userProfileQuery = `
            SELECT DISTINCT phone_number 
            FROM user_profile 
            WHERE mac_id IN (?)
        `;

        db.query(userProfileQuery, [macIds], (userProfileErr, userProfileResults) => {
            if (userProfileErr) {
                console.error('Error fetching user profiles:', userProfileErr);
                return res.status(500).json({ error: 'Database query error while fetching user profiles' });
            }

            const phoneNumbers = userProfileResults.map(row => row.phone_number);

            if (phoneNumbers.length === 0) {
                return res.status(404).json({ error: 'No phone numbers found for provided mac_ids' });
            }

            // Get primary_ids from event_list table using phone_numbers
            const eventListQuery = `
                SELECT primary_id 
                FROM user_list 
                WHERE phone_number IN (?)
            `;

            db.query(eventListQuery, [phoneNumbers], (eventListErr, eventListResults) => {
                if (eventListErr) {
                    console.error('Error fetching event list:', eventListErr);
                    return res.status(500).json({ error: 'Database query error while fetching event list' });
                }

                const primaryIds = eventListResults.map(row => row.primary_id);

                if (primaryIds.length === 0) {
                    return res.status(404).json({ error: 'No events found for provided phone numbers' });
                }

                // Get today's date at 12:00 AM in the Asia/Kolkata timezone
                const today = new Date();
                today.setUTCHours(0, 0, 0, 0); // Convert UTC to IST (UTC +5:30)

                const formatter = new Intl.DateTimeFormat('en-US', {
                    timeZone: 'Asia/Kolkata',
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                });

                // Format to YYYY-MM-DD 00:00:00
                const formattedToday = formatter.format(today);
                const [month, day, year] = formattedToday.split('/');

                const sqlFormattedToday = `${year}-${month}-${day} 00:00:00`;

                console.log(`Fetching events created after: ${sqlFormattedToday}`);

                // Get event_id, event_name, and created_at from user_event table using primary_ids
                const userEventQuery = `
                    SELECT event_id, event_name, created_at 
                    FROM user_event 
                    WHERE event_id IN (?) AND created_at > ?
                `;

                db.query(userEventQuery, [primaryIds, sqlFormattedToday], (userEventErr, userEventResults) => {
                    if (userEventErr) {
                        console.error('Error fetching user events:', userEventErr);
                        return res.status(500).json({ error: 'Database query error while fetching user events' });
                    }

                    if (userEventResults.length === 0) {
                        return res.status(404).json({ error: 'No events found for provided primary_ids or all events are outdated' });
                    }

                    // Map event_id, event_name, and created_at into a structured response
                    const events = userEventResults.map(row => ({
                        event_id: row.event_id,
                        event_name: row.event_name,
                        created_at: row.created_at,
                    }));

                    // Send the events as response
                    res.status(200).json({ userEventResults });
                });
            });
        });
    });
});


app.post('/getUserList', (req, res) => {
     // Log request body

    const token = req.headers['authorization']; // Extract token from headers

    if (!token) {
        console.error('Authorization token is missing');
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
            console.error('Invalid or expired token');
            return res.status(403).json({ error: 'Invalid or expired token' });
        }

        const phone_number = authResult[0].phone_number; // Retrieve phone_number from query result
        const macIds = req.body.map((item) => item.mac_id);

        if (!macIds || macIds.length === 0) {
            console.error('mac_id list is empty');
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

                console.log('Response Body:', response); // Log response body
                res.json(response);
            });
        });
    });
});

app.post('/login-send-otp', (req, res) => {
    const { phoneNumber } = req.body;

    console.log('Request Body:', req.body); // Log the request body

    if (!phoneNumber) {
        const errorResponse = { error: 'Phone number is required' };
        console.error('Response:', errorResponse);
        return res.status(400).json(errorResponse);
    }

    const otp = Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit OTP
    console.log(`Generated OTP for ${phoneNumber}:`, otp);

    // Check if the phone number exists in the user_profile table
    const checkUserQuery = 'SELECT phone_number FROM user_profile WHERE phone_number = ?';

    db.query(checkUserQuery, [phoneNumber], (err, result) => {
        if (err) {
            console.error('Database Query Error:', err);
            const errorResponse = { error: 'Database query error' };
            console.error('Response:', errorResponse);
            return res.status(500).json(errorResponse);
        }

        if (result.length === 0) {
            const errorResponse = { error: 'Phone number not found' };
            console.warn(`Phone number ${phoneNumber} not found in database.`);
            console.warn('Response:', errorResponse);
            return res.status(404).json(errorResponse);
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
                console.error('Database Query Error:', err);
                const errorResponse = { error: 'Database query error' };
                console.error('Response:', errorResponse);
                return res.status(500).json(errorResponse);
            }

            const successResponse = { message: `OTP sent to ${phoneNumber}`, otp };
            console.log('Response:', successResponse);
            res.json(successResponse);
        });
    });
});



app.listen(3001, () => {
    console.log('Server Running');
});
