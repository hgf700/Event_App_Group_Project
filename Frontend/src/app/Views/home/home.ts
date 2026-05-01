import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import {
  FormBuilder,
  FormGroup,
  Validators,
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

  constructor(
    private route: ActivatedRoute,
    private router: Router,
  ) {}

  loginWithGoogle() {
    window.location.href = 'https://localhost:7051/api/auth/signin-google';
  }

  registerUser() {
    this.router.navigate(['/register-user']);
  }

  loginUser() {
    this.router.navigate(['/login-user']);
  }
}