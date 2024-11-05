import crypto from 'node:crypto'

import dbLocal from 'db-local';
import bcrypt from 'bcrypt'

const { Schema } = new dbLocal({ path : './db'})

import { SALT_ROUNDS } from './config.js';
//import Schema from "db-local/lib/modules/schema";

const User = Schema('User', {
    _id : { type : String, required: true },
    username : { type : String, required: true },
    password : { type : String, required: true },

})
export class UserRepository{
    static async create ({ username, password}) {
        Validation.username(username)
        Validation.password(password)
        
        const user = User.findOne( {username} )
        if (user) throw new Error('El username ya existe')

        const id = crypto.randomUUID()
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

        User.create({
            _id : id,
            username,
            password: hashedPassword
        }).save()
        return id;

    }
    static async login ({ username, password}) {
        Validation.username(username)
        Validation.password(password)

        const user = User.findOne({username})
        if (!user) throw new Error("No existe el username")

        const isValid = await bcrypt.compareSync(password, user.password)
        if (!isvalid) throw new Error('Contraseña incorrecta')

        const {password: _, ...publicUser } = user
        return publicUser
    }
}

class Validation {
    static username (username){
        if (typeof username != 'string') throw new Error('EL username debe ser un string')
        if (username.length < 3) throw new Error('El username debe tener mas de 3 caracteres')
    }

    static password (password){
        if (typeof password != 'string') throw new Error('La contraseña debe ser un string')
        if (password.length < 8) throw new Error('La contraseña debe tener mas de 8 de largo')
    }
}