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
    //this.tokenService.clearToken();
    window.location.href = this.HOST + '/api/auth/jwt/login';
  }

  async logout() {
    this.tokenService.clearToken();
    window.location.href = this.HOST + '/api/auth/jwt/logout';
  }

  // call this to refresh tokens
  // if 401 -- session expired, need to re-authenticate
  async refreshTokens() {
    const token = this.tokenService.getToken();
    if (!token) return;

    const response = await fetch(this.HOST + '/api/auth/jwt/refresh', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      credentials: 'include',
    });

    this.checkUpdateToken(response);

    const data = await response.json();
    console.log('Refresh response:', data);
  }

  checkUpdateToken = (response: Response) => {
    if (!response.ok) {
      this.tokenRefreshed = false;
      this.tokenService.clearToken();

      if (response.status === 401) {
        // Session expired, redirect to login
        this.login(); // Redirect to login
      } else {
        // invalid token or other error, nothing to do other than login again
        this.login();
      }

      return;
    }

    // this check needs to be done to see if the token has been refreshed
    if (response.headers.get('X-New-Access-Token') !== null) {
      const newAccessToken = response.headers.get('X-New-Access-Token');
      if (newAccessToken) {
        this.tokenService.setToken(newAccessToken as string); // Update the token in memory
        this.tokenRefreshed = true;
      }
    }
  };

  // example of protected route
  async fetchUserInfo() {
    const token = this.tokenService.getToken();

    // if not token is found in memory, we need to redirect to login
    if (!token) {
      this.login();
    }

    const response = await fetch(this.HOST + '/api/user', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      credentials: 'include', // withCredentials: true
    });

    this.checkUpdateToken(response);

    // actual data from the endpoint
    const data = await response.json();
    console.log('User info response:', data);
  }

  // example of protected route
  async fetchAdminResource() {
    const token = this.tokenService.getToken();

    // if not token is found in memory, we need to redirect to login
    if (!token) {
      this.login();
    }

    const response = await fetch(this.HOST + '/api/admin/resource', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      credentials: 'include', // withCredentials: true
    });

    this.checkUpdateToken(response);

    const data = await response.json();
    console.log(data);
  }
}
