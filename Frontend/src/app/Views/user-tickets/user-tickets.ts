import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { getEventDto } from '../../Dto/getEventDto';
import { UserService } from '../../Services/UserService';

@Component({
  selector: 'app-user-tickets',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './user-tickets.html',
  styleUrl: './user-tickets.css',
})
export class UserTickets implements OnInit{
  events: getEventDto[] = [];
  loading = false;

  constructor(
    private router: Router,
    private cdr: ChangeDetectorRef,
    private userService: UserService,
  ) {}

  ngOnInit(): void {
    this.getUserTickets();
  }

  returnToLoginCallback() {
    this.router.navigate(['/login-callback']);
  }

  getUserTickets() {
    this.loading = true;
    this.userService.currentUserTickets().subscribe({
      next: (data) => {
        this.events = data ?? [];
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        alert('Nie udało się currentUserTickets');
      },
    });
  }
  
}
