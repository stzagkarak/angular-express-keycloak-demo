import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root',
})
export class TokenService {
  private token: string | null = null;

  // DO NOT STORE THE TOKEN IN LOCAL STORAGE, IT IS NOT SECURE
  // Use this service to manage the token in memory only

  setToken(token: string) {
    this.token = token;
  }

  getToken(): string | null {
    return this.token;
  }

  clearToken() {
    this.token = null;
  }
}
