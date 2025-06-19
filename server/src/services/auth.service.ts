import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { JWT_SECRET } from '../config';
import { InvalidCredentialsError } from '../errors/auth/InvalidCredentialsError';
import { InvalidTokenError } from '../errors/auth/InvalidTokenError';
import { UserAlreadyRegisteredError } from '../errors/auth/UserAlreadyRegisteredError';
import { UserNotFoundError } from '../errors/auth/UserNotFoundError';
import { prisma } from '../utils/prisma';

const TOKEN_EXPIRATION = '1h';

export class AuthService {
    static async registerUser(email: string, password: string, name: string) {
        // Validação do email vazio
        if (!email) {
            throw new InvalidCredentialsError('O email não pode ser vazio');
        }
    
        // Validação do nome vazio
        if (!name) {
            throw new InvalidCredentialsError('O nome não pode ser vazio');
        }
    
        // Verifica se o email já está registrado
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            throw new UserAlreadyRegisteredError(); // Lança erro se o usuário já existe
        }
    
        // Criptografa a senha
        const hashedPassword = await bcrypt.hash(password, 10);
    
        // Cria o usuário no banco de dados
        const user = await prisma.user.create({
            data: { email, password: hashedPassword, name },
        });
    
        // Gera o token JWT
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION });
    
        // Retorna o token e os dados do usuário
        return {
            token,
            user: { id: user.id, email: user.email, name: user.name },
        };
    }
    
    

    static async loginUser(email: string, password: string) {
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            throw new InvalidCredentialsError();
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            throw new InvalidCredentialsError();
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION });

        return {
            token,
            user: { id: user.id, email: user.email, name: user.name },
        };
    }

    static async getUserById(userId: number) {
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { id: true, email: true, name: true, createdAt: true },
        });

        if (!user) {
            throw new UserNotFoundError();
        }

        return user;
    }

    static async getUserFromTokenPayload(userId: number) {
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { id: true, email: true, name: true },
        });

        if (!user) {
            throw new UserNotFoundError();
        }

        return user;
    }

    static refreshToken(oldToken: string) {
        try {
            const decoded = jwt.verify(oldToken, JWT_SECRET, { ignoreExpiration: true }) as {
                userId: number;
            };
            const newToken = jwt.sign({ userId: decoded.userId }, JWT_SECRET, {
                expiresIn: TOKEN_EXPIRATION,
            });

            return newToken;
        } catch {
            throw new InvalidTokenError();
        }
    }
}
