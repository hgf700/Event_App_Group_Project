import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { UserService } from '../../Services/UserService';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';

@Component({
  selector: 'app-edit-user-email',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './edit-user-email.html',
  styleUrl: './edit-user-email.css',
})
export class EditUserEmail {
  editUserEmailForm!: FormGroup;
  submitted = false;

  constructor(
      private fb: FormBuilder,
      private router: Router,
      private userService: UserService,
    ) {
      this.editUserEmailForm = this.fb.group({
        newEmail: ['', ],
      });
    }


  generateJWT(){
    const tokenFromStorage = localStorage.getItem('jwt');

    console.log({
      tokenFromStorage,
    });

    if (!tokenFromStorage) {
      console.error('Brak tokena – użytkownik niezalogowany');
      return;
    }
  }

  onSubmit() {
    this.submitted = true;

    if (this.editUserEmailForm.invalid) {
      console.log(this.editUserEmailForm.errors);
      return;
    }

    const newEmail = this.editUserEmailForm.value.newEmail;

    this.userService.editCurrentUserEmail(newEmail).subscribe({
      next: (res) => {
        this.generateJWT();
        console.log('success change newEmail');
      },
      error: (err) => alert(err.error),
    });
  }
}
