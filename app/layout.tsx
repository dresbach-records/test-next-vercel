import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'DEEVO — Test Next Vercel',
  description: 'Projeto de teste Next.js + Vercel + Neon',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="pt-BR"><body>{children}</body></html>;
}
