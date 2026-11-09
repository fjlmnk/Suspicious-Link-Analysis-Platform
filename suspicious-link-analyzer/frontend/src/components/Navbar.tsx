import { useState, useRef, useEffect } from 'react';
import { Link, NavLink } from 'react-router-dom';
import { Shield, Menu, X, ChevronDown, User, Building2 } from 'lucide-react';
import { useUser } from '@/services/userContext';
import { UserRole } from '@/types';

export default function Navbar() {
  const { user, isEmployee, setRole } = useUser();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [roleDropdownOpen, setRoleDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setRoleDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleRoleChange = async (role: UserRole) => {
    try {
      if (role === UserRole.COMPANY_EMPLOYEE) {
        await setRole(role, 'My Company', 'Security');
      } else {
        await setRole(role);
      }
    } catch {
      // Error handled in context
    }
    setRoleDropdownOpen(false);
  };

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
      isActive
        ? 'bg-cyan-600/20 text-cyan-400'
        : 'text-slate-300 hover:text-white hover:bg-slate-800'
    }`;

  return (
    <nav className="sticky top-0 z-50 bg-slate-900/95 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2 group">
            <Shield className="w-7 h-7 text-cyan-400 group-hover:text-cyan-300 transition-colors" />
            <span className="text-lg font-bold text-white hidden sm:block">
              Suspicious Link Analyzer
            </span>
            <span className="text-lg font-bold text-white sm:hidden">SLA</span>
          </Link>

          {/* Desktop Nav Links */}
          <div className="hidden md:flex items-center gap-1">
            <NavLink to="/" end className={navLinkClass}>
              Dashboard
            </NavLink>
            <NavLink to="/history" className={navLinkClass}>
              History
            </NavLink>
            <NavLink to="/demo" className={navLinkClass}>
              Demo Mode
            </NavLink>
          </div>

          {/* Right side: Role Switcher + Mobile toggle */}
          <div className="flex items-center gap-3">
            {/* Role Switcher Dropdown */}
            <div className="relative" ref={dropdownRef}>
              <button
                onClick={() => setRoleDropdownOpen(!roleDropdownOpen)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 
                           bg-slate-800/50 hover:bg-slate-800 text-sm text-slate-300 
                           hover:text-white transition-all duration-200"
              >
                {isEmployee ? (
                  <Building2 className="w-4 h-4 text-cyan-400" />
                ) : (
                  <User className="w-4 h-4 text-slate-400" />
                )}
                <span className="hidden sm:inline">
                  {isEmployee ? 'Employee' : 'Regular'}
                </span>
                <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${roleDropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {roleDropdownOpen && (
                <div className="absolute right-0 mt-2 w-56 bg-slate-800 border border-slate-700 rounded-xl shadow-xl shadow-black/40 overflow-hidden">
                  <div className="p-2">
                    <button
                      onClick={() => handleRoleChange(UserRole.REGULAR)}
                      className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                        !isEmployee
                          ? 'bg-cyan-600/20 text-cyan-400'
                          : 'text-slate-300 hover:bg-slate-700 hover:text-white'
                      }`}
                    >
                      <User className="w-4 h-4" />
                      <div className="text-left">
                        <div className="font-medium">Regular User</div>
                        <div className="text-xs text-slate-500">Basic scan features</div>
                      </div>
                    </button>
                    <button
                      onClick={() => handleRoleChange(UserRole.COMPANY_EMPLOYEE)}
                      className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                        isEmployee
                          ? 'bg-cyan-600/20 text-cyan-400'
                          : 'text-slate-300 hover:bg-slate-700 hover:text-white'
                      }`}
                    >
                      <Building2 className="w-4 h-4" />
                      <div className="text-left">
                        <div className="font-medium">Company Employee</div>
                        <div className="text-xs text-slate-500">PDF reports & security team</div>
                      </div>
                    </button>
                  </div>
                  {user && (
                    <div className="border-t border-slate-700 px-4 py-2 text-xs text-slate-500">
                      Session: {user.session_id.slice(0, 8)}...
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Mobile menu button */}
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="md:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu */}
      {mobileOpen && (
        <div className="md:hidden border-t border-slate-800 bg-slate-900/95 backdrop-blur-md">
          <div className="px-4 py-3 space-y-1">
            <NavLink
              to="/"
              end
              className={navLinkClass}
              onClick={() => setMobileOpen(false)}
            >
              Dashboard
            </NavLink>
            <NavLink
              to="/history"
              className={navLinkClass}
              onClick={() => setMobileOpen(false)}
            >
              History
            </NavLink>
            <NavLink
              to="/demo"
              className={navLinkClass}
              onClick={() => setMobileOpen(false)}
            >
              Demo Mode
            </NavLink>
          </div>
        </div>
      )}
    </nav>
  );
}
