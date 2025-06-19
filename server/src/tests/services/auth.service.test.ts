import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { AuthService } from '../../services/auth.service';
import { prisma } from '../../utils/prisma';
import { UserAlreadyRegisteredError } from '../../errors/auth/UserAlreadyRegisteredError';
import { InvalidCredentialsError } from '../../errors/auth/InvalidCredentialsError';
import { InvalidTokenError } from '../../errors/auth/InvalidTokenError';
import { UserNotFoundError } from '../../errors/auth/UserNotFoundError';
import { JWT_SECRET } from '../../config'; 


UserNotFoundError
jest.mock('bcryptjs');
jest.mock('jsonwebtoken');
jest.mock('../../utils/prisma', () => ({
    prisma: {
        user: {
            findUnique: jest.fn(),
            create: jest.fn(),
        },
    },
}));

describe('AuthService', () => {
    const mockUser = {
        id: 1,
        email: 'usuario@exemplo.teste',
        name: 'Usuário Exemplo',
        createdAt: new Date(),
    };
    const password = 'senha';
    const hashedPassword = 'senha-criptografada';

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('registerUser', () => {
        it('deve cadastrar um novo usuário e retornar o seu token', async () => {
            // Arrange (preparar)
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
            (bcrypt.hash as jest.Mock).mockResolvedValue(hashedPassword);
            (prisma.user.create as jest.Mock).mockResolvedValue({
                ...mockUser,
                password: hashedPassword,
            });
            (jwt.sign as jest.Mock).mockReturnValue('mockedToken');

            // Act (agir)
            const result = await AuthService.registerUser(mockUser.email, password, mockUser.name);

            // Assert (verificar)
            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { email: mockUser.email },
            });
            expect(prisma.user.create).toHaveBeenCalledWith({
                data: {
                    email: mockUser.email,
                    password: hashedPassword,
                    name: mockUser.name,
                },
            });
            expect(result.token).toBe('mockedToken');
            expect(result.user).toEqual({
                id: mockUser.id,
                email: mockUser.email,
                name: mockUser.name,
            });
        });

        it('deve lançar erro ao cadastrar um usuário já cadastrado', async () => {
                // Simulação: retornando um usuário já existente no banco de dados
                (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
            
                // Espera que o erro 'UserAlreadyRegisteredError' seja lançado
                await expect(
                    AuthService.registerUser(mockUser.email, password, mockUser.name)
                ).rejects.toBeInstanceOf(UserAlreadyRegisteredError);
            
                // Verifica se o findUnique foi chamado corretamente com o email do usuário
                expect(prisma.user.findUnique).toHaveBeenCalledWith({
                    where: { email: mockUser.email },
                });
            });
            
    });

    describe('loginUser', () => {
        it('deve realizar o login do usuário e retornar o seu token', async () => {
            // Arrange (preparar)
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
            (bcrypt.compare as jest.Mock).mockResolvedValue(true);
            (jwt.sign as jest.Mock).mockReturnValue('mockedToken');

            // Act (agir)
            const result = await AuthService.loginUser(mockUser.email, password);

            // Assert (verificar)
            expect(result.token).toBe('mockedToken');
            expect(result.user).toEqual({
                id: mockUser.id,
                email: mockUser.email,
                name: mockUser.name,
            });
        });

        it('deve lançar erro ao inserir credenciais inválidas ao realizar o login', async () => {
            // Preparar: retornando um usuário válido no banco de dados
            const mockUser = {
                id: 1,
                email: 'usuario@exemplo.teste',
                name: 'Usuário Exemplo',
                createdAt: new Date(),
                password: hashedPassword, // Usando a senha criptografada diretamente aqui
            };
        
            // Simulando o comportamento do banco de dados
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
            (bcrypt.compare as jest.Mock).mockResolvedValue(false); // Simula que a senha está errada
        
            // Agir: tentar fazer login com credenciais inválidas
            await expect(
                AuthService.loginUser(mockUser.email, password)
            ).rejects.toBeInstanceOf(InvalidCredentialsError);
        
            // Verificar: se o findUnique foi chamado com o email correto
            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { email: mockUser.email },
            });
        
            // Verificar: se o bcrypt.compare foi chamado para comparar a senha
            expect(bcrypt.compare).toHaveBeenCalledWith(password, mockUser.password);
        });

        it('deve lançar erro ao realizar login de um usuário não encontrado', async () => {
            // Preparar: Simula que o usuário não foi encontrado no banco de dados
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
        
            // Agir: Tentar fazer login com um email que não existe no banco de dados
            await expect(
                AuthService.loginUser('usuario@naoencontrado.com', 'senha')
            ).rejects.toBeInstanceOf(InvalidCredentialsError);
        
            // Verificar: Se o método findUnique foi chamado com o email correto, garante que o banco foi consultado
            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { email: 'usuario@naoencontrado.com' },
            });
        });

        it('deve lançar erro ao realizar login com a senha incorreta', async () => {
            // Preparar: Simulando que o usuário existe no banco de dados, mas a senha está incorreta
            const mockUser = {
                id: 1,
                email: 'usuario@exemplo.teste',
                name: 'Usuário Exemplo',
                createdAt: new Date(),
                password: hashedPassword, // Senha armazenada no banco de dados (criptografada)
            };
        
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser); // Simula que o usuário foi encontrado
            (bcrypt.compare as jest.Mock).mockResolvedValue(false); // Simula que a senha fornecida é incorreta
        
            // Agir: Tentar fazer login com um email e uma senha incorreta
            await expect(
                AuthService.loginUser(mockUser.email, 'senhaIncorreta') // Senha incorreta
            ).rejects.toBeInstanceOf(InvalidCredentialsError); // Espera que o erro seja lançado
        
            // Verificar: Se o findUnique foi chamado com o email correto
            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { email: mockUser.email },
            });
        
            // Verificar: Se o bcrypt.compare foi chamado com a senha fornecida e a senha armazenada no banco
            expect(bcrypt.compare).toHaveBeenCalledWith('senhaIncorreta', mockUser.password);
        });

        it('deve lançar erro ao realizar login de um usuário com senha em branco', async () => {
            const mockUser = {
                id: 1,
                email: 'usuario@exemplo.com',
                name: 'Usuário Exemplo',
                createdAt: new Date(),
                password: hashedPassword,
            };
        
            // Simulando o comportamento do banco de dados
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
            (bcrypt.compare as jest.Mock).mockResolvedValue(false); // Simula senha incorreta
        
            // Agir: tentar fazer login com uma senha em branco
            await expect(
                AuthService.loginUser(mockUser.email, '') // Senha em branco
            ).rejects.toBeInstanceOf(InvalidCredentialsError); // Espera que o erro seja lançado
        
            // Verificar: Se o findUnique foi chamado com o email correto
            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { email: mockUser.email },
            });
        
            // Verificar: Se o bcrypt.compare foi chamado com a senha fornecida e a senha armazenada no banco
            expect(bcrypt.compare).toHaveBeenCalledWith('', mockUser.password); // Comparando senha em branco
        });
        
        it('deve lançar erro ao tentar cadastrar usuário com email vazio', async () => {
            // Dados inválidos (email vazio)
            const dadosInvalidos = {
                email: '', // Email vazio
                password: 'senha',
                name: 'Usuário Teste',
            };
        
            // Ação
            await expect(
                AuthService.registerUser(dadosInvalidos.email, dadosInvalidos.password, dadosInvalidos.name)
            ).rejects.toBeInstanceOf(InvalidCredentialsError); // Espera que o erro InvalidCredentialsError seja lançado
        });

        it('deve lançar erro ao tentar cadastrar usuário com nome vazio', async () => {
            // Dados inválidos (nome vazio)
            const dadosInvalidos = {
                email: 'usuario@exemplo.com', // Email válido
                password: 'senha',
                name: '', // Nome vazio
            };
        
            // Ação
            await expect(
                AuthService.registerUser(dadosInvalidos.email, dadosInvalidos.password, dadosInvalidos.name)
            ).rejects.toBeInstanceOf(InvalidCredentialsError); // Espera que o erro InvalidCredentialsError seja lançado
        });

        
        it('deve lançar erro ao tentar cadastrar usuário com senha muito curta', async () => {
            // Dados inválidos (senha muito curta)
            const dadosInvalidos = {
                email: 'usuario@exemplo.com',
                password: '123', // Senha com menos de 6 caracteres
                name: 'Usuário Teste',
            };
        
            // Ação
            await expect(
                AuthService.registerUser(dadosInvalidos.email, dadosInvalidos.password, dadosInvalidos.name)
            ).rejects.toBeInstanceOf(InvalidCredentialsError); // Espera que o erro InvalidCredentialsError seja lançado
        });
        
        
        
        
        
    });

    describe('getUserById', () => {
        it('deve retornar o usuário com base no seu identificador', async () => {
            // Arrange (preparar)
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

            // Act (agir)
            const user = await AuthService.getUserById(1);

            // Assert (verificar)
            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { id: mockUser.id },
                select: { id: true, email: true, name: true, createdAt: true },
            });
            expect(user).toEqual({
                id: mockUser.id,
                email: mockUser.email,
                name: mockUser.name,
                createdAt: mockUser.createdAt,
            });
        });

        it('deve lançar erro ao buscar usuário pelo identificador se o usuário não existir', async () => {
            const invalidUserId = 999; // ID de usuário que não existe no banco de dados
        
            // Simulando que o usuário não foi encontrado no banco
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
        
            // Agir: Tentar buscar o usuário pelo ID
            await expect(
                AuthService.getUserById(invalidUserId)
            ).rejects.toBeInstanceOf(UserNotFoundError); // Espera que o erro UserNotFoundError seja lançado
        
            // Verificar: Se o prisma foi chamado com o ID correto
            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { id: invalidUserId },
                select: { id: true, email: true, name: true, createdAt: true },
            });
        });
        
    });

    describe('getUserFromTokenPayload', () => {
        it('deve retornar dados do usuário com base no identificador retornado pelo token', async () => {
            // Arrange (preparar)
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

            // Act (agir)
            const user = await AuthService.getUserFromTokenPayload(1);

            // Assert (verificar)
            expect(user).toEqual({
                id: mockUser.id,
                email: mockUser.email,
                name: mockUser.name,
                createdAt: mockUser.createdAt,
            });
        });

        it('deve lançar erro ao buscar usuário pelo token se o usuário não existir', async () => {
            const invalidUserId = 999; // ID de usuário que não existe no banco de dados
        
            // Simulando a verificação do token JWT
            const decodedToken = { userId: invalidUserId };
        
            // Simulando que o usuário não foi encontrado no banco de dados
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
        
            // Agir: Tentar buscar o usuário pelo token
            await expect(
                AuthService.getUserFromTokenPayload(decodedToken.userId)
            ).rejects.toBeInstanceOf(UserNotFoundError); // Espera que o erro UserNotFoundError seja lançado
        
            // Verificar: Se o prisma foi chamado com o ID correto extraído do token
            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { id: invalidUserId },
                select: { id: true, email: true, name: true },
            });
        });
        
    });

    describe('refreshToken', () => {

        it('deve retornar um token novo ao atualizar token se o token antigo for válido', () => {
            // Arrange (preparar)
            (jwt.verify as jest.Mock).mockReturnValue({ userId: 1 });
            (jwt.sign as jest.Mock).mockReturnValue('tokenNovo');

            // Act (agir)
            const newToken = AuthService.refreshToken('tokenAntigo');

            // Assert (verificar)
            expect(newToken).toBe('tokenNovo');
        });
        

    });

    
});
