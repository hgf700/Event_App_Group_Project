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
import { AuthService } from '../../Services/AuthService'

@Component({
  selector: 'app-login-user',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './login-user.html',
  styleUrl: './login-user.css',
})
export class LoginUser {
  loginUserForm!: FormGroup;
  submitted = false;

  constructor(
    private fb: FormBuilder,
    private route: ActivatedRoute,
    private router: Router,
    private authService: AuthService,
  ) {
    this.loginUserForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required]],
    });
  }

  onSubmit() {
    this.submitted = true;

    if (this.loginUserForm.invalid) {
      console.log(this.loginUserForm.errors);
      return;
    }

    console.log(this.loginUserForm.valid);

    const email = this.loginUserForm.value.email;
    const password = this.loginUserForm.value.password;

      this.authService.loginUserNorm(email,password).subscribe({
        next: (res) => {
          localStorage.setItem('jwt', res.token);
          this.router.navigate(['/login-callback']);
        },
      error: (err) => alert(err.error),
    });
  }
}
