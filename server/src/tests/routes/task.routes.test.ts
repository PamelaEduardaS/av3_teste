/* eslint-disable @typescript-eslint/no-explicit-any */

// Mock do middleware de autenticação para simular a autenticação durante o teste
jest.mock('../../middlewares/auth.middleware', () => ({
    authenticate: (req: any, res: any, next: any) => {
        req.userId = testUser.id ?? 1;
        next();
    },
}));

import { StatusCodes } from 'http-status-codes';
import request from 'supertest';
import app from '../../app';
import { prisma } from '../../utils/prisma';
import { setupTestDB, disconnectTestDB, testUser } from '../setup.test.db';

beforeAll(async () => {
    await setupTestDB();
});

afterAll(async () => {
    await disconnectTestDB();
});

describe('TaskController', () => {
    describe('POST /api/tasks', () => {
        it('deve criar tarefa com dados válidos', async () => {
            // Arrange (preparar)
            const taskData = {
                title: `Tarefa válida ${new Date()}`,
                description: 'Essa é uma tarefa válida',
                completed: false,
                priority: 'low',
            };

            // Act (agir)
            const response = await request(app).post('/api/tasks').send(taskData);

            // Assert (verificar)
            expect(response.statusCode).toBe(StatusCodes.CREATED);
            expect(response.body).toEqual({
                ...taskData,
                id: expect.any(Number),
                userId: 1,
                dueDate: null,
                createdAt: expect.any(String),
                updatedAt: expect.any(String),
            });

            const taskInDB = await prisma.task.findFirst({ where: { title: taskData.title } });
            expect(taskInDB).toEqual(
                expect.objectContaining({
                    ...taskData,
                    id: expect.any(Number),
                    userId: 1,
                    createdAt: expect.any(Date),
                    updatedAt: expect.any(Date),
                }),
            );
        });
    });
});

describe('DELETE /api/tasks/:id', () => {
    it('deve deletar a tarefa com id válido e verificar se a tarefa também foi excluida do banco', async () => {
        // Arrange (preparar)
        const taskData = {
            title: `Tarefa para deletar ${new Date()}`,
            description: 'Essa tarefa será deletada',
            completed: false,
            priority: 'low',
        };

        // Cria uma tarefa primeiro
        const createdResponse = await request(app).post('/api/tasks').send(taskData);
        const createdTask = createdResponse.body;
        const taskId = createdTask.id; // Pega o ID da tarefa criada

        // Act (agir) - Deleta a tarefa
        const response = await request(app).delete(`/api/tasks/${taskId}`);

        // Assert (verificar)
        expect(response.statusCode).toBe(StatusCodes.NO_CONTENT);  // Espera status 204 (sem conteúdo)
        
        // Verifica se a tarefa foi removida do banco de dados
        const taskInDB = await prisma.task.findUnique({ where: { id: taskId } });
        expect(taskInDB).toBeNull();  // Verifica se a tarefa foi deletada do banco
    });

    it('deve retornar erro 404 quando a tarefa não existir', async () => {
        // Arrange (preparar)
        const invalidTaskId = 9999;  // Um ID de tarefa que não existe no banco

        // Act (agir)
        const response = await request(app).delete(`/api/tasks/${invalidTaskId}`);

        // Assert (verificar)
        expect(response.statusCode).toBe(StatusCodes.NOT_FOUND);  // Espera erro 404
        expect(response.body).toEqual({ message: 'Tarefa não encontrada' });  // Verifica a mensagem de erro
    });
});

