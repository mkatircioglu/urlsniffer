NAME := urlsniffer
SPECFILE = $(NAME).spec
VERSION := $(shell rpm -q --specfile --qf '%{VERSION}\n' *.spec | head -n 1)
RELEASE := $(shell rpm -q --specfile --qf '%{RELEASE}\n' *.spec | head -n 1)

dist rpm: $(NAME)-$(VERSION)-$(RELEASE).rpm

$(NAME)-$(VERSION).tar.gz:
	mkdir -p $(NAME)-$(VERSION)
	rsync -av --exclude=.svn --exclude=.git --exclude=*.tar.gz --exclude=$(NAME)-$(VERSION)/ ./ $(NAME)-$(VERSION)
	tar -czf $@ $(NAME)-$(VERSION)
	rm -fr $(NAME)-$(VERSION)

$(NAME)-$(VERSION)-$(RELEASE).rpm: $(NAME)-$(VERSION).tar.gz
	mkdir -p build
	rpmbuild -bb --define '_sourcedir $(PWD)' \
		--define '_builddir $(PWD)/build' \
		--define '_srcrpmdir $(PWD)' \
		--define '_rpmdir $(PWD)' \
		--define '_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' \
		$(SPECFILE)

srpm: $(NAME)-$(VERSION)-$(RELEASE).src.rpm
$(NAME)-$(VERSION)-$(RELEASE).src.rpm: $(NAME)-$(VERSION).tar.gz
	rpmbuild -bs --define "_sourcedir $$(pwd)" \
		--define "_srcrpmdir $$(pwd)" \
		$(SPECFILE)

clean:
	rm -f $(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)-$(RELEASE).*.rpm
	rm -rf build/
