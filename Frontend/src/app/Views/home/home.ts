import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../Services/AuthService'

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './home.html',
  styleUrl: './home.css',
})
export class Home {
  // private apiUrl = 'https://localhost:7051/api/v1/auth';
   
  constructor(
    private router: Router,
    private authService: AuthService,
  ) {}

  loginWithGoogle() {
    this.authService.loginWithGoogleOauth();
  }

  registerUserView() {
    this.router.navigate(['/register-user']);
  }

  loginUserView() {
    this.router.navigate(['/login-user']);
  }
}