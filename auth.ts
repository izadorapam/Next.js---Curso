import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import postgres from 'postgres';

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string): Promise<User | null> {
  const users = await sql<User[]>`
    SELECT * FROM users WHERE email = ${email}
  `;
  return users[0] || null;
}

// Configuração do NextAuth
export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'text', placeholder: 'email@example.com' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        // Validação de entrada com Zod
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (!parsedCredentials.success) {
          console.log('Invalid input format');
          return null;
        }

        const { email, password } = parsedCredentials.data;
        const user = await getUser(email);

        if (!user) {
          console.log('User not found');
          return null;
        }

        const passwordsMatch = await bcrypt.compare(password, user.password);

        if (!passwordsMatch) {
          console.log('Incorrect password');
          return null;
        }

        return user;
      },
    }),
  ],
  session: {
  },
  pages: {
    signIn: '/auth/signin',
    error: '/auth/error',
  },
});
