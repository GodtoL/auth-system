import crypto from 'node:crypto'

import dbLocal from 'db-local';
import bcrypt from 'bcrypt'

const { Schema } = new dbLocal({ path : './db'})

import { SALT_ROUNDS } from './config.js';

const User = Schema('User', {
    _id : { type : String, required: true },
    email : { type : String, required: true },
    password : { type : String, required: true },

})
export class UserRepository{
    static async create ({ email, password}) {
        Validation.email(email)
        Validation.password(password)
        
        const user = User.findOne( {email} )
        if (user) throw new Error('El username ya existe')

        const id = crypto.randomUUID()
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

        User.create({
            _id : id,
            email,
            password: hashedPassword
        }).save()
        return id;

    }
    static async login ({ email, password}) {
        Validation.email(email)
        Validation.password(password)

        const user = User.findOne({email})
        if (!user) throw new Error("No existe el email")

        const isValid = await bcrypt.compareSync(password, user.password)
        if (!isValid) throw new Error('Contraseña incorrecta')

        const {password: _, ...publicUser } = user
        return publicUser
    }
}

class Validation {
    static email (email){
        if (typeof email != 'string') throw new Error('EL email debe ser un string')
        if (email.length < 3) throw new Error('El email debe tener mas de 3 caracteres')
    }

    static password (password){
        if (typeof password != 'string') throw new Error('La contraseña debe ser un string')
        if (password.length < 8) throw new Error('La contraseña debe tener mas de 8 de largo')
    }
}