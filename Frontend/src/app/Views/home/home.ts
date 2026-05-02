import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import {
  FormGroup,
  ReactiveFormsModule,
} from '@angular/forms';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './home.html',
  styleUrl: './home.css',
})
export class Home {
  developingLoginForm!: FormGroup;
  submitted = false;
  private apiUrl = 'https://localhost:7051/api/auth';


  constructor(
    private route: ActivatedRoute,
    private router: Router,
  ) {}

  loginWithGoogleOauth() {
    window.location.href = `${this.apiUrl}/sign-in-google`;
  }

  registerUserView() {
    this.router.navigate(['/register-user']);
  }

  loginUserView() {
    this.router.navigate(['/login-user']);
  }
}