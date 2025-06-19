import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { TaskNotFoundError } from '../errors/task/TaskNotFoundError';
import { TaskService } from '../services/task.service';

export const createTask = async (req: Request, res: Response): Promise<void> => {
    const userId = req.userId;
    if (!userId) {
        res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Não autorizado' });

        return;
    }

    try {
        const task = await TaskService.createTask(userId, req.body);
        res.status(StatusCodes.CREATED).json(task);
    } catch (error) {
        console.error('Erro ao criar tarefa:', error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Erro no servidor' });
    }
};

export const getTasks = async (req: Request, res: Response): Promise<void> => {
    const userId = req.userId;
    if (!userId) {
        res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Não autorizado' });

        return;
    }

    try {
        const tasks = await TaskService.getTasks(userId, req.query);
        res.json(tasks);
    } catch (error) {
        console.error('Erro ao buscar tarefas:', error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Erro no servidor' });
    }
};

export const getTaskById = async (req: Request, res: Response): Promise<void> => {
    const userId = req.userId;
    if (!userId) {
        res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Não autorizado' });

        return;
    }

    try {
        const task = await TaskService.getTaskById(userId, parseInt(req.params.id));
        res.json(task);
    } catch (error) {
        if (error instanceof TaskNotFoundError) {
            res.status(StatusCodes.NOT_FOUND).json({ message: error.message });
        } else {
            console.error('Erro ao buscar tarefa:', error);
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Erro no servidor' });
        }
    }
};

export const updateTask = async (req: Request, res: Response): Promise<void> => {
    const userId = req.userId;
    if (!userId) {
        res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Não autorizado' });

        return;
    }

    try {
        const updatedTask = await TaskService.updateTask(userId, parseInt(req.params.id), req.body);
        res.json(updatedTask);
    } catch (error) {
        console.error('Erro ao atualizar tarefa:', error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Erro no servidor' });
    }
};

export const deleteTask = async (req: Request, res: Response): Promise<void> => {
    const userId = req.userId;
    if (!userId) {
        res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Não autorizado' });
        return;
    }

    try {
        await TaskService.deleteTask(userId, parseInt(req.params.id));
        res.status(StatusCodes.NO_CONTENT).send();
    } catch (error) {
        if (error instanceof TaskNotFoundError) {
            res.status(StatusCodes.NOT_FOUND).json({ message: error.message });
        } else {
            console.error('Erro ao deletar tarefa:', error);
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Erro no servidor' });
        }
    }
};

