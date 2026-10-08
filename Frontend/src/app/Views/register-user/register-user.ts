import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { AuthService } from '../../Services/AuthService';
import { registerUserValidator } from '../../Validators/registerUserValidator';

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
    this.registerUserForm = this.fb.group(
      {
        email: ['', [
          Validators.required,
          // Validators.email
        ]],
        password: ['', [
          Validators.required,
        // Validators.minLength(8),
        // Validators.maxLength(20),
        // Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).+$/)
        ]],
        confirmPassword: ['', [
          Validators.required,
          // Validators.minLength(8),
        // Validators.maxLength(20),
        // Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).+$/)
        ]],
      },
      { validators: registerUserValidator },
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
        localStorage.setItem('email', res.email!);
        localStorage.setItem('userRole', res.userRole!);

        this.router.navigate(['/login-callback']);
      },
      error: (err) => alert(err.error),
    });
  }
}
