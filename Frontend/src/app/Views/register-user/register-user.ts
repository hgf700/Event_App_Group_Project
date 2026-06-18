import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { AuthService } from '../../Services/AuthService';
import {registerPasswordMatchValidator} from '../../Validators/registerPasswordMatchValidator';

@Component({
  selector: 'app-register-user',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './register-user.html',
  styleUrl: './register-user.css',
})
export class RegisterUser {
  registerUserForm!: FormGroup;
  submitted = false;

  constructor(
    private fb: FormBuilder,
    private router: Router,
    private authService: AuthService,
  ) {
    this.registerUserForm = this.fb.group({
      email: ['', [Validators.required]],
      password: ['', [Validators.required]],
      confirmPassword: ['', [Validators.required]],
    },
      { validators: registerPasswordMatchValidator }
    );
  }
  // , Validators.email
  onSubmit() {
    this.submitted = true;

    if (this.registerUserForm.invalid) {
      console.log(this.registerUserForm.errors);
      return;
    }

    const email = this.registerUserForm.value.email;
    const password = this.registerUserForm.value.password;

    this.authService.registerUserNorm(email, password).subscribe({
      next: (res) => {
        localStorage.setItem('jwt', res.jwt);

        this.router.navigate(['/login-callback']);
      },
      error: (err) => alert(err.error),
    });
  }
}
