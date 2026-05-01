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
    private route: ActivatedRoute,
    private router: Router,
  ) {
    this.registerUserForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required]],
      confirmPassword: ['', [Validators.required]],

    });
  }



    onSubmit() {
    this.submitted = true;

    console.log(this.registerUserForm.errors);
    console.log(this.registerUserForm.valid);

    const email = this.registerUserForm.value.email;

    // this.devLogin.developingLogin(email).subscribe({
    //   next: (res) => {
    //     localStorage.setItem('jwt', res.token);
    //     this.router.navigate(['/login-callback']);
    //   },
    //   error: (err) => alert(err.error),
    // });
  }
}
