import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import {
  loginUser,
  registerUser,
  getCurrentUser,
  logoutUser,
  isSimulationMode,
  setAuthToken,
  getAuthToken,
  removeAuthToken,
} from '../services/api';

const AuthContext = createContext(null);

// Standard mock personas for simulation / quick test
export const DEMO_PERSONAS = {
  admin: {
    user_id: 'usr-admin-001',
    username: 'admin',
    email: 'admin@storeshare.net',
    role: 'admin',
    provider_id: null,
    is_active: true,
  },
  provider: {
    user_id: 'usr-prov-alpha-002',
    username: 'provider_alpha',
    email: 'alpha@nodes.io',
    role: 'provider',
    provider_id: 'provider-primary-alpha',
    is_active: true,
  },
  consumer: {
    user_id: 'usr-cons-alice-003',
    username: 'alice',
    email: 'alice@crypto.org',
    role: 'consumer',
    provider_id: null,
    is_active: true,
  },
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('expo_current_user');
    if (saved) {
      try { return JSON.parse(saved); } catch (e) { return null; }
    }
    // Default to admin demo persona on initial load for exploration
    return DEMO_PERSONAS.admin;
  });

  const [token, setTokenState] = useState(() => getAuthToken());
  const [isLoading, setIsLoading] = useState(false);
  const [authError, setAuthError] = useState(null);
  const [accessDeniedMessage, setAccessDeniedMessage] = useState(null);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalTab, setAuthModalTab] = useState('login'); // 'login' | 'register'

  // Persist user in localStorage for browser refresh
  useEffect(() => {
    if (user) {
      localStorage.setItem('expo_current_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('expo_current_user');
    }
  }, [user]);

  // Check backend session if token exists and not in pure simulation mode
  const checkSession = useCallback(async () => {
    if (isSimulationMode() || !getAuthToken()) return;
    setIsLoading(true);
    try {
      const me = await getCurrentUser();
      if (me && me.user_id) {
        setUser(me);
        setAuthError(null);
      }
    } catch (err) {
      console.warn('Backend session verification failed:', err.message);
      if (err.message.includes('401') || err.message.includes('revoked')) {
        setUser(null);
        removeAuthToken();
        setTokenState(null);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  const login = async (usernameOrEmail, password) => {
    setIsLoading(true);
    setAuthError(null);
    try {
      const res = await loginUser({ username_or_email: usernameOrEmail, password });
      if (res.access_token) {
        setAuthToken(res.access_token);
        setTokenState(res.access_token);
      }
      if (res.user) {
        setUser(res.user);
      }
      setAuthModalOpen(false);
      return res;
    } catch (err) {
      setAuthError(err.message || 'Login failed. Check your credentials.');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (username, email, password) => {
    setIsLoading(true);
    setAuthError(null);
    try {
      const res = await registerUser({ username, email, password });
      // After registration, auto login or prompt login
      setAuthModalTab('login');
      return res;
    } catch (err) {
      setAuthError(err.message || 'Registration failed.');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setIsLoading(true);
    try {
      if (!isSimulationMode() && token) {
        await logoutUser();
      }
    } catch (err) {
      console.warn('Logout error from server:', err);
    } finally {
      removeAuthToken();
      setTokenState(null);
      setUser(null);
      setIsLoading(false);
    }
  };

  const switchDemoRole = (roleKey) => {
    const persona = DEMO_PERSONAS[roleKey];
    if (persona) {
      setUser(persona);
      setAuthError(null);
      setAccessDeniedMessage(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        role: user ? user.role : null,
        token,
        isAuthenticated: !!user,
        isLoading,
        authError,
        setAuthError,
        accessDeniedMessage,
        setAccessDeniedMessage,
        authModalOpen,
        setAuthModalOpen,
        authModalTab,
        setAuthModalTab,
        login,
        register,
        logout,
        switchDemoRole,
        checkSession,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
