import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { UserService } from '../../Services/UserService';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import {changePasswordMatchValidator} from '../../Validators/changePasswordMatchValidator';

@Component({
  selector: 'app-edit-user-password',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './edit-user-password.html',
  styleUrl: './edit-user-password.css',
})
export class EditUserPassword {
  editUserPasswordForm!: FormGroup;
  submitted = false;

  constructor(
      private fb: FormBuilder,
      private router: Router,
      private userService: UserService,
    ) {
      this.editUserPasswordForm = this.fb.group({
        newPassword: ['', ],
        repeatNewPassword: ['', ],
      },
      { validators: changePasswordMatchValidator }
      );
    }

  returnToLoginCallback() {
    this.router.navigate(['/login-callback']);
  }

  onSubmit() {
    this.submitted = true;

    if (this.editUserPasswordForm.invalid) {
      console.log(this.editUserPasswordForm.errors);
      return;
    }

    const newPassword = this.editUserPasswordForm.value.newPassword;
    const oldPassword = this.editUserPasswordForm.value.oldPassword;


    this.userService.editCurrentUserPassword(oldPassword, newPassword).subscribe({
      next: (res) => {
        console.log('success');
      },
      error: (err) => alert(err.error),
    });
  }
}
