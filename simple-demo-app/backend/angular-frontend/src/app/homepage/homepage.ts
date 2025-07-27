import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

import { ActivatedRoute, Router } from '@angular/router';
import { TokenService } from '../services/token-ref';
import { environment } from '../../environments/environment';

@Component({
  selector: 'app-homepage',
  imports: [CommonModule],
  templateUrl: './homepage.html',
  styleUrl: './homepage.css',
})
export class Homepage {
  HOST: string = environment.HOST || 'http://localhost:3001'; // Default to localhost if not set
  tokenFound = false;
  tokenRefreshed = false;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private tokenService: TokenService
  ) {
    // Check if current path is "/auth/callback"
    if (this.router.url.startsWith('/auth/callback')) {
      this.route.queryParams.subscribe((params) => {
        const token = params['token'];

        if (token) {
          tokenService.setToken(token); // Store the token in memory ( NOT IN LOCAL STORAGE CUZ IT IS NOT SECURE )
          this.tokenFound = tokenService.getToken() !== null;
          console.log('Token from callback:', token);

          // you may want to clear to token from the URL after processing.
          // ...
        } else {
          this.tokenFound = tokenService.getToken() !== null;
        }
      });
    }
  }

  // call login method initially to start the OIDC flow
  // also call this method when 401 errors occur in protected routes
  login() {
    this.tokenService.clearToken();
    window.location.href = this.HOST + '/api/auth/jwt/login';
  }

  async logout() {
    this.tokenService.clearToken();
    window.location.href = this.HOST + '/api/auth/jwt/logout';
  }

  // call this to refresh tokens if 403 error occurs
  async refreshTokens() {
    const token = this.tokenService.getToken();
    if (!token) return;

    try {
      const response = await fetch(this.HOST + '/api/auth/jwt/refresh', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        credentials: 'include',
      });

      const data = await response.json();
      console.log('Refresh response:', data);

      // update the token in memory
      this.tokenService.setToken(data.accessToken); // Update the token in memory
      this.tokenRefreshed = true;
    } catch (error) {
      // if refresh fails, clear the token and call the login method to redirect and start the OIDC flow
      console.error('Refresh failed:', error);

      this.tokenRefreshed = false;
      this.tokenService.clearToken();

      // you may want to redirect to login page and/or show a message
      this.login(); // Redirect to login to start the OIDC flow again
    }
  }

  // example of protected route
  async fetchUserInfo() {
    const token = this.tokenService.getToken();

    // if not token is found in memory, we need to redirect to login
    if (!token) {
      this.login();
    }

    try {
      const response = await fetch(this.HOST + '/api/user', {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        credentials: 'include', // withCredentials: true
      });

      if (!response.ok) {
        throw new Error('Network response was not ok');
      }

      const data = await response.json();
      console.log('User info response:', data);
    } catch (error) {
      console.error('Fetch user info failed:', error);
    }
  }

  // example of protected route
  async fetchAdminResource() {
    const token = this.tokenService.getToken();

    // if not token is found in memory, we need to redirect to login
    if (!token) {
      this.login();
      return;
    }

    try {
      const response = await fetch(this.HOST + '/api/admin/resource', {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        credentials: 'include', // withCredentials: true
      });

      if (!response.ok) {
        throw new Error('Network response was not ok');
      }

      const data = await response.json();
      console.log(data);
    } catch (error) {
      console.error('Fetch protected route failed:', error);
    }
  }
}
