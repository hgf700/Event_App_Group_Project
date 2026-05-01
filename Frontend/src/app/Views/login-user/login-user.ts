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
  ) {
    this.loginUserForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required]],
      
    });
  }




    onSubmit() {
    this.submitted = true;

    console.log(this.loginUserForm.errors);
    console.log(this.loginUserForm.valid);

    const email = this.loginUserForm.value.email;

    // this.devLogin.developingLogin(email).subscribe({
    //   next: (res) => {
    //     localStorage.setItem('jwt', res.token);
    //     this.router.navigate(['/login-callback']);
    //   },
    //   error: (err) => alert(err.error),
    // });
  }
}
