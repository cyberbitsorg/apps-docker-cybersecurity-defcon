import { useState, useEffect, useCallback, useRef } from "react";
import { getArticles, markArticleRead, markAllRead } from "../api/articles";
import type { Article, ArticlesResponse } from "../types/article";

const POLL_INTERVAL = 5 * 60 * 1000;
const TICK_INTERVAL = 60 * 1000;
const PAGE_SIZE = 20;

export function useArticles() {
  const [data, setData] = useState<ArticlesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const [page, setPage] = useState(1);
  const intervalRef = useRef<ReturnType<typeof setInterval>>();
  const tickRef = useRef<ReturnType<typeof setInterval>>();

  const fetchArticles = useCallback(async (resetTimer?: boolean, targetPage?: number) => {
    const currentPage = targetPage ?? page;
    try {
      const result = await getArticles({
        limit: PAGE_SIZE,
        offset: (currentPage - 1) * PAGE_SIZE,
      });
      if (resetTimer) {
        result.last_refreshed_at = new Date().toISOString();
      }
      setData(result);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load articles");
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    fetchArticles();
    intervalRef.current = setInterval(fetchArticles, POLL_INTERVAL);
    tickRef.current = setInterval(() => setTick((n) => n + 1), TICK_INTERVAL);
    return () => {
      clearInterval(intervalRef.current);
      clearInterval(tickRef.current);
    };
  }, [fetchArticles]);

  const goToPage = useCallback((newPage: number) => {
    setPage(newPage);
    setLoading(true);
    fetchArticles(false, newPage);
  }, [fetchArticles]);

  const toggleRead = useCallback(async (id: string, isRead: boolean) => {
    // Optimistic update
    setData((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        articles: prev.articles.map((a) =>
          a.id === id ? { ...a, is_read: isRead } : a
        ),
      };
    });

    try {
      await markArticleRead(id, isRead);
    } catch {
      // Revert on failure
      setData((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          articles: prev.articles.map((a) =>
            a.id === id ? { ...a, is_read: !isRead } : a
          ),
        };
      });
    }
  }, []);

  const markAll = useCallback(async (isRead: boolean) => {
    setData((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        articles: prev.articles.map((a) => ({ ...a, is_read: isRead })),
      };
    });
    try {
      await markAllRead(isRead);
    } catch {
      fetchArticles();
    }
  }, [fetchArticles]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return {
    articles: data?.articles ?? [],
    total: data?.total ?? 0,
    lastRefreshed: data?.last_refreshed_at ?? null,
    loading,
    error,
    page,
    totalPages,
    goToPage,
    refresh: fetchArticles,
    toggleRead,
    markAll,
  };
}
