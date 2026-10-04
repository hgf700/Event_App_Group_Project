import { Component, signal } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';

import { AuthService } from '../../Services/AuthService';

@Component({
  selector: 'app-layout',
  standalone: true,
  imports: [RouterOutlet, RouterLink],
  templateUrl: './layout.html',
  styleUrl: './layout.css',
})
export class Layout {
  userEmailData = signal(localStorage.getItem('email') ?? '');
  userRole = signal(localStorage.getItem('userRole'));

  constructor(
    public authService: AuthService

  ) {}

  isLogged(){
    return this.authService.isLogged();
  }

  isAdmin(){
    return this.authService.isAdmin();
  }

  // isLoggedIn(): boolean {
  //   return this.authService.isAuthenticated();
  // }

  logout(): void {
    this.authService.logout();
  }
}
