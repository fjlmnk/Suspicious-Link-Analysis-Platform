import React, { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { api } from '@/services/api';
import { UserRole, type User } from '@/types';

interface UserContextType {
  user: User | null;
  loading: boolean;
  error: string | null;
  isEmployee: boolean;
  setRole: (role: UserRole, companyName?: string, department?: string) => Promise<void>;
  refreshUser: () => Promise<void>;
}

const UserContext = createContext<UserContextType | undefined>(undefined);

export function UserProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const isEmployee = user?.role === UserRole.COMPANY_EMPLOYEE;

  const refreshUser = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await api.getMe();
      setUser(response.data);
    } catch {
      // User doesn't exist yet, create a session
      try {
        const response = await api.createSession();
        setUser(response.data);
      } catch (createErr) {
        const message = createErr instanceof Error ? createErr.message : 'Failed to initialize session';
        setError(message);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  const setRole = useCallback(async (role: UserRole, companyName?: string, department?: string) => {
    try {
      setError(null);
      const response = await api.createSession({
        role,
        company_name: companyName,
        department: department,
      });
      setUser(response.data);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to update role';
      setError(message);
      throw err;
    }
  }, []);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  return (
    <UserContext.Provider value={{ user, loading, error, isEmployee, setRole, refreshUser }}>
      {children}
    </UserContext.Provider>
  );
}

export function useUser(): UserContextType {
  const context = useContext(UserContext);
  if (context === undefined) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
}
