import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { AdminService } from '../../../Services/AdminService';
import { getAdminUserDto } from '../../../Dto/getAdminUserDto';

@Component({
  selector: 'app-users',
  imports: [],
  templateUrl: './users.html',
  styleUrl: './users.css',
})
export class Users implements OnInit {
  users: getAdminUserDto[] = [];
  loading = false;

  constructor(
    private adminService: AdminService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.loadUsers();
  }

  loadUsers(): void {
    this.loading = true;
    this.adminService.getUsers().subscribe({
      next: response => {
        this.users = response;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: err => {
        console.error(err);
        this.loading = false;
      }
    });
  }

  blockUser(id: string): void {
    if (!confirm('Czy na pewno chcesz zablokować tego użytkownika?')) {
      return;
    }

    this.adminService.blockUser(id).subscribe({
      next: () => {
        this.loadUsers();
      },
      error: err => {
        console.error(err);
        alert('Nie udało się zablokować użytkownika.');
      }
    });
  }

  deleteUser(id: string): void {
    if (!confirm('Czy na pewno chcesz usunąć tego użytkownika?')) {
      return;
    }

    this.adminService.deleteUser(id).subscribe({
      next: () => {
        this.loadUsers();
      },
      error: err => {
        console.error(err);
        alert('Nie udało się usunąć użytkownika.');
      }
    });
  }
}
