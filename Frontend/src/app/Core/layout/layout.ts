import { Component } from '@angular/core';
import { AuthService } from '../../Services/AuthService';

@Component({
  selector: 'app-layout',
  imports: [],
  templateUrl: './layout.html',
  styleUrl: './layout.css',
})
export class Layout {
  constructor(public authService: AuthService) {}

  // isLoggedIn(): boolean {
  //   return this.authService.isAuthenticated();
  // }

  // get userEmail(): string {
  //   return this.authService.userEmail();
  // }

  // logout(): void {
  //   this.authService.logout();
  // }

}
