import { useState, useEffect, useCallback } from 'react';

export function useTypewriter(text: string, speed = 40, delay = 0) {
  const [displayed, setDisplayed] = useState('');
  const [started, setStarted] = useState(false);

  const start = useCallback(() => setStarted(true), []);

  useEffect(() => {
    if (!started) return;
    let i = 0;
    const timeout = setTimeout(() => {
      const interval = setInterval(() => {
        if (i < text.length) {
          setDisplayed(text.slice(0, i + 1));
          i++;
        } else {
          clearInterval(interval);
        }
      }, speed + Math.random() * 20);
      return () => clearInterval(interval);
    }, delay);
    return () => clearTimeout(timeout);
  }, [text, speed, delay, started]);

  return { displayed, start, isDone: displayed.length === text.length };
}
