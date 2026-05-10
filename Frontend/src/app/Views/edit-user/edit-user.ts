import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { UserService } from '../../Services/UserService';

@Component({
  selector: 'app-edit-user',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './edit-user.html',
  styleUrl: './edit-user.css',
})
export class EditUser {
  editUserForm!: FormGroup;
  submitted = false;

  constructor(
      private fb: FormBuilder,
      private route: ActivatedRoute,
      private router: Router,
      private userService: UserService,
    ) {
      this.editUserForm = this.fb.group({
        newEmail: ['', ],
        currentPassword: ['', ],
        newPassword: ['', ],
      });
    }
  
returnToLoginCallback() {
    this.router.navigate(['/login-callback']);
  }

  onSubmit() {
    this.submitted = true;

    if (this.editUserForm.invalid) {
      console.log(this.editUserForm.errors);
      return;
    }

    const newEmail = this.editUserForm.value.newEmail;
    const currentPassword = this.editUserForm.value.currentPassword;
    const newPassword = this.editUserForm.value.newPassword;

    this.userService.editCurrentUser(newEmail, currentPassword, newPassword).subscribe({
      next: (res) => {
        console.log('success');
      },
      error: (err) => alert(err.error),
    });
  }

}
