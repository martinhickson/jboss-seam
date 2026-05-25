-- Test data for booking application
insert into Customer (username, password, name) values ('gavin', 'foobar', 'Gavin King');
insert into Customer (username, password, name) values ('demo', 'demo', 'Demo User');

insert into Hotel (id, name, address, city, state, zip, country, price) values (1, 'W New York - Union Square', '201 Park Avenue South', 'NY', 'NY', '10011', 'USA', 401.00);
insert into Hotel (id, name, address, city, state, zip, country, price) values (2, 'W New York', '541 Lexington Avenue', 'NY', 'NY', '10022', 'USA', 450.00);
insert into Hotel (id, name, address, city, state, zip, country, price) values (3, 'Hotel Beacon', '2130 Broadway', 'NY', 'NY', '10023', 'USA', 180.00);
