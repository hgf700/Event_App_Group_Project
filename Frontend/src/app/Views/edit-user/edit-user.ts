import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { UserService } from '../../Services/UserService';

@Component({
  selector: 'app-edit-user',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './edit-user.html',
  styleUrl: './edit-user.css',
})
export class EditUser {

  constructor(
      private route: ActivatedRoute,
      private router: Router,
    ) {}
  
  changeUserEmail() {
    this.router.navigate(['/edit-user-email']);
  }

  changeUserPassword() {
    this.router.navigate(['/edit-user-password']);
  }




}
