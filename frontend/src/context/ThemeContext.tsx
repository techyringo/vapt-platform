'use client';

import { createContext, useCallback, useContext, useEffect, useState } from 'react';

export type Theme = 'dark' | 'light';
export type ColorGrade = 'slate' | 'warm' | 'violet' | 'emerald';

export interface ColorGradeOption {
  id: ColorGrade;
  label: string;
  accentHex: string;
  bgHint: string;
}

export const COLOR_GRADES: ColorGradeOption[] = [
  { id: 'slate',   label: 'Cool Slate',   accentHex: '#0891b2', bgHint: '#f8fafc' },
  { id: 'warm',    label: 'Warm Amber',   accentHex: '#d97706', bgHint: '#faf7f0' },
  { id: 'violet',  label: 'Violet',       accentHex: '#7c3aed', bgHint: '#faf8ff' },
  { id: 'emerald', label: 'Sec. Emerald', accentHex: '#059669', bgHint: '#f0faf5' },
];

interface ThemeContextValue {
  theme: Theme;
  colorGrade: ColorGrade;
  toggleTheme: () => void;
  setColorGrade: (grade: ColorGrade) => void;
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: 'dark',
  colorGrade: 'slate',
  toggleTheme: () => {},
  setColorGrade: () => {},
});

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<Theme>('dark');
  const [colorGrade, setColorGradeState] = useState<ColorGrade>('slate');

  useEffect(() => {
    try {
      const t = localStorage.getItem('vapt-theme') as Theme | null;
      const g = localStorage.getItem('vapt-color-grade') as ColorGrade | null;
      if (t === 'dark' || t === 'light') setTheme(t);
      if (g && COLOR_GRADES.some(c => c.id === g)) setColorGradeState(g);
    } catch {}
  }, []);

  useEffect(() => {
    const html = document.documentElement;
    html.classList.remove('dark', 'light');
    COLOR_GRADES.forEach(g => html.classList.remove(`light-${g.id}`));

    html.classList.add(theme);
    if (theme === 'light') {
      html.classList.add(`light-${colorGrade}`);
    }
    try {
      localStorage.setItem('vapt-theme', theme);
    } catch {}
  }, [theme, colorGrade]);

  const toggleTheme = useCallback(() => {
    setTheme(t => (t === 'dark' ? 'light' : 'dark'));
  }, []);

  const setColorGrade = useCallback((grade: ColorGrade) => {
    setColorGradeState(grade);
    try { localStorage.setItem('vapt-color-grade', grade); } catch {}
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, colorGrade, toggleTheme, setColorGrade }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  return useContext(ThemeContext);
}
