import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { AdminService } from '../../../Services/AdminService';
import { getAdminUserDto } from '../../../Dto/getAdminUserDto';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-blocked-users',
  imports: [FormsModule],
  templateUrl: './blocked-users.html',
  styleUrl: './blocked-users.css',
})
export class BlockedUsers implements OnInit {
  blockedUsers: getAdminUserDto[] = [];
  loading = false;
  searchText = '';
  filteredBlockedUsers: getAdminUserDto[] = [];

  constructor(
    private adminService: AdminService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.loadBlockedUsers();
  }

  filterUsers() {
    const search = this.searchText.toLowerCase().trim();

    this.filteredBlockedUsers = this.blockedUsers.filter(user =>
      user.email.toLowerCase().includes(search) ||
      user.id.toLowerCase().includes(search) 
    );
  }

  clearSearch() {
    this.searchText = '';
    this.filteredBlockedUsers = this.blockedUsers;
  }

  loadBlockedUsers(): void {
    this.loading = true;
    this.adminService.getBlockedUsers().subscribe({
      next: (response) => {
        this.blockedUsers = response;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error(err);
        this.loading = false;
      },
    });
  }

  unblockUser(id: string): void {
    this.adminService.unblockUser(id).subscribe({
      next: () => {
        this.loadBlockedUsers();
      },
      error: (err) => {
        console.error(err);
        alert('Nie udało się odblokować użytkownika.');
      },
    });
  }

  deleteUser(id: string): void {
    if (!confirm('Czy na pewno chcesz usunąć tego użytkownika?')) {
      return;
    }

    this.adminService.deleteUser(id).subscribe({
      next: () => {
        this.loadBlockedUsers();
      },
      error: (err) => {
        console.error(err);
        alert('Nie udało się usunąć użytkownika.');
      },
    });
  }
}
