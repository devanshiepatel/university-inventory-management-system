import express from 'express'
import mysql from 'mysql'
import cors from 'cors'

const app =express()

const db = mysql.createConnection({
    host:"localhost",
    user:"root",
    password:'1234',
    database:'universitydb'

})

app.use(express.json());
app.use(cors());

app.get('/',(req,res)=>{
    res.json("Hello, this is the backend")
})

app.get('/faculties',(req,res)=>{
    const q= "SELECT * FROM faculties;"
    db.query(q,(err,data)=>{
        if(err)
            return res.json(err)
        return res.json(data)
    })
})
app.get('/departments/:faculty_id',(req,res)=>{
    const faculty_id = req.params.faculty_id;
    const q= "SELECT * FROM departments WHERE faculty_id = ?"
    db.query(q,[faculty_id],(err,data)=>{
        if(err)
            return res.json(err)
        return res.json(data)
    })
})

app.get('/rooms/:dept_id', (req, res) => {
    const department_id = req.params.dept_id;
    
    if (!department_id) {
        return res.status(400).json({ error: "Invalid department ID" });
    }

    const q = "SELECT * FROM rooms WHERE dept_id = ?";
    
    db.query(q, [department_id], (err, data) => {
        if (err) {
            console.error("Error fetching rooms:", err);
            return res.status(500).json({ error: "Database query failed" });
        }
        if (data.length === 0) {
            return res.status(404).json({ message: "No rooms found for this department" });
        }
        console.log("Rooms API Response:", data); // Debugging
        return res.json(data);
    });
});

app.post("/faculties",(req,res)=>{
    const q= "INSERT INTO faculties(`faculty_id`,`f_name`,`dean_name`) VALUES (?)"
    const values=[
        req.body.faculty_id,
        req.body.f_name,
        req.body.dean_name,
    ];
    db.query(q,[values],(err,data)=>{
        if(err)
            return res.json(err)
        return res.json('data has been entered successfully!')
    })
})
app.listen(8800, ()=>{
    console.log("connected to backend!")
})