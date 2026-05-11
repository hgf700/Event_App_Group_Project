import { Component } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';

import { LayoutService } from '../../Services/LayoutService';

@Component({
  selector: 'app-layout',
  standalone: true,
  imports: [
    RouterOutlet,
    RouterLink,
  ],
  templateUrl: './layout.html',
  styleUrl: './layout.css',
})
export class Layout {

  constructor(
    public layoutService: LayoutService
  ) {}

  isLoggedIn(): boolean {
    return this.layoutService.isAuthenticated();
  }

  get userEmail(): string {
    return this.layoutService.userEmail();
  }

  logout(): void {
    this.layoutService.logout();
  }
}