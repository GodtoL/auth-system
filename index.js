import express from 'express'
import { UserRepository } from './user-repository.js'

const app = express()
app.use(express.json())

const port = process.env.port ?? 3001

app.get('/', (req, res) => {
    res.send('Hola node js')
})
app.post('/login', async (req, res) => {
    try{

    } catch (error){
        h
    }
})
app.post('/register', async (req, res) => {
    const {username, password} = req.body
    console.log(req.body)

    try {
        const id = UserRepository.create({ username, password})
        res.send( { id })
    } catch (error){
        res.status(400).send(error.message)
    }
})
app.post('/logout', (req, res) => {})

app.post('/protected', (req, res) => {})

app.listen(port, () => {
    console.log(`Server running on port ${port}`)
})